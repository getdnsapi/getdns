#include <getdns_libevent.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

int main(){ return(0); }

/* Function definitions */

getdns_return_t
getdns_general(
  struct getdns_context      *context,
  const char                 *name,
  uint16_t                   request_type,
  struct getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(request_type); UNUSED_PARAM(extensions); UNUSED_PARAM(userarg);
UNUSED_PARAM(transaction_id); UNUSED_PARAM(callback); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_address(
  struct getdns_context      *context,
  const char                 *name,
  struct getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(extensions); UNUSED_PARAM(userarg);
UNUSED_PARAM(transaction_id); UNUSED_PARAM(callback); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_hostname(
  struct getdns_context      *context,
  struct getdns_dict         *address,
  struct getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{ UNUSED_PARAM(context); UNUSED_PARAM(address); UNUSED_PARAM(extensions); UNUSED_PARAM(userarg);
UNUSED_PARAM(transaction_id); UNUSED_PARAM(callback); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_service(
  struct getdns_context      *context,
  const char                 *name,
  struct getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(extensions); UNUSED_PARAM(userarg);
UNUSED_PARAM(transaction_id); UNUSED_PARAM(callback); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_create(
    struct getdns_context   **context,
    int                     set_from_os
)
{ UNUSED_PARAM(context); UNUSED_PARAM(set_from_os); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_create_with_memory_functions(
  struct getdns_context  **context,
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
  struct getdns_context  **context,
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
	struct getdns_context  *context
)
{ UNUSED_PARAM(context); }

getdns_return_t
getdns_cancel_callback(
	struct getdns_context      *context,
	getdns_transaction_t       transaction_id
)
{ UNUSED_PARAM(context); UNUSED_PARAM(transaction_id); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_general_sync(
  struct getdns_context  *context,
  const char             *name,
  uint16_t               request_type,
  struct getdns_dict     *extensions,
  struct getdns_dict     **response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(request_type); UNUSED_PARAM(extensions);
UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_address_sync(
  struct getdns_context  *context,
  const char             *name,
  struct getdns_dict     *extensions,
  struct getdns_dict     **response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(extensions);
UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_hostname_sync(
  struct getdns_context  *context,
  struct getdns_dict     *address,
  struct getdns_dict     *extensions,
  struct getdns_dict     **response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(address); UNUSED_PARAM(extensions);
UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_service_sync(
  struct getdns_context  *context,
  const char             *name,
  struct getdns_dict     *extensions,
  struct getdns_dict     **response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(extensions);
UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

void
getdns_free_sync_request_memory(
  struct getdns_dict     *response
)
{ UNUSED_PARAM(response); }

getdns_return_t getdns_list_get_length(const struct getdns_list *this_list, size_t *answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_get_data_type(const struct getdns_list *this_list, size_t index, getdns_data_type *answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_get_dict(const struct getdns_list *this_list, size_t index, struct getdns_dict **answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_get_list(const struct getdns_list *this_list, size_t index, struct getdns_list **answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_get_bindata(const struct getdns_list *this_list, size_t index, struct getdns_bindata **answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_get_int(const struct getdns_list *this_list, size_t index, uint32_t *answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_names(const struct getdns_dict *this_dict, struct getdns_list **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_data_type(const struct getdns_dict *this_dict, const char *name, getdns_data_type *answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_dict(const struct getdns_dict *this_dict, const char *name, struct getdns_dict **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_list(const struct getdns_dict *this_dict, const char *name, struct getdns_list **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_bindata(const struct getdns_dict *this_dict, const char *name, struct getdns_bindata **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_int(const struct getdns_dict *this_dict, const char *name, uint32_t *answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

struct getdns_list * getdns_list_create()
{ return NULL; }

struct getdns_list * getdns_list_create_with_context(
  struct getdns_context *context
)
{ UNUSED_PARAM(context); return NULL; }

struct getdns_list * getdns_list_create_with_memory_functions(
  void *(*malloc)(size_t),
  void *(*realloc)(void *, size_t),
  void (*free)(void *)
)
{ UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return NULL; }

struct getdns_list * getdns_list_create_with_extended_memory_functions(
  void *userarg,
  void *(*malloc)(void *userarg, size_t),
  void *(*realloc)(void *userarg, void *, size_t),
  void (*free)(void *userarg, void *)
)
{ UNUSED_PARAM(userarg);
  UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return NULL; }

void getdns_list_destroy(struct getdns_list *this_list)
{ UNUSED_PARAM(this_list); }

getdns_return_t getdns_list_set_dict(struct getdns_list *this_list, size_t index, const struct getdns_dict *child_dict)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(child_dict); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_set_list(struct getdns_list *this_list, size_t index, const struct getdns_list *child_list)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(child_list); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_set_bindata(struct getdns_list *this_list, size_t index, const struct getdns_bindata *child_bindata)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(child_bindata); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_set_int(struct getdns_list *this_list, size_t index, uint32_t child_uint32)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(child_uint32); return GETDNS_RETURN_GOOD; }

struct getdns_dict * getdns_dict_create()
{ return NULL; }

struct getdns_dict * getdns_dict_create_with_context(
  struct getdns_context *context
)
{ UNUSED_PARAM(context); return NULL; }

struct getdns_dict * getdns_dict_create_with_memory_functions(
  void *(*malloc)(size_t),
  void *(*realloc)(void *, size_t),
  void (*free)(void *)
)
{ UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return NULL; }

struct getdns_dict * getdns_dict_create_with_extended_memory_functions(
  void *userarg,
  void *(*malloc)(void *userarg, size_t),
  void *(*realloc)(void *userarg, void *, size_t),
  void (*free)(void *userarg, void *)
)
{ UNUSED_PARAM(userarg);
  UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return NULL; }

void getdns_dict_destroy(struct getdns_dict *this_dict)
{ UNUSED_PARAM(this_dict); }

getdns_return_t getdns_dict_set_dict(struct getdns_dict *this_dict, const char *name, const struct getdns_dict *child_dict)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_dict); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_set_list(struct getdns_dict *this_dict, const char *name, const struct getdns_list *child_list)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_list); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_set_bindata(struct getdns_dict *this_dict, const char *name, const struct getdns_bindata *child_bindata)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_bindata); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_set_int(struct getdns_dict *this_dict, const char *name, uint32_t child_uint32)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_uint32); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_remove_name(struct getdns_dict *this_dict, const char *name)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); return GETDNS_RETURN_GOOD; }

char *
getdns_convert_dns_name_to_fqdn(
  const char  *name_from_dns_response
)
{ UNUSED_PARAM(name_from_dns_response); return NULL; }

char *
getdns_convert_fqdn_to_dns_name(
  const char  *fqdn_as_string
)
{ UNUSED_PARAM(fqdn_as_string); return NULL; }

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
  struct getdns_bindata  *record_to_validate,
  struct getdns_list     *bundle_of_support_records,
  struct getdns_list     *trust_anchor_rdatas
)
{ UNUSED_PARAM(record_to_validate); UNUSED_PARAM(bundle_of_support_records); UNUSED_PARAM(trust_anchor_rdatas);
return GETDNS_RETURN_GOOD; }


char *
getdns_pretty_print_dict(
	const struct getdns_dict     *some_dict
)
{ UNUSED_PARAM(some_dict); return NULL; }

char *
getdns_display_ip_address(
  const struct getdns_bindata    *bindata_of_ipv4_or_ipv6_address
)
{ UNUSED_PARAM(bindata_of_ipv4_or_ipv6_address); return NULL; }

getdns_return_t
getdns_context_set_context_update_callback(
  struct getdns_context  *context,
  void                   (*value)(struct getdns_context *context, uint16_t changed_item)
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_resolution_type(
  struct getdns_context  *context,
  uint16_t               value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_namespaces(
  struct getdns_context  *context,
  size_t                 namespace_count,
  uint16_t               *namespaces
)
{ UNUSED_PARAM(context); UNUSED_PARAM(namespace_count); UNUSED_PARAM(namespaces);
return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_dns_transport(
  struct getdns_context  *context,
  uint16_t               value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_limit_outstanding_queries(
  struct getdns_context  *context,
  uint16_t               limit
)
{ UNUSED_PARAM(context); UNUSED_PARAM(limit); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_timeout(
  struct getdns_context  *context,
  uint16_t               timeout
)
{ UNUSED_PARAM(context); UNUSED_PARAM(timeout); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_follow_redirects(
  struct getdns_context  *context,
  uint16_t               value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_dns_root_servers(
  struct getdns_context  *context,
  struct getdns_list     *addresses
)
{ UNUSED_PARAM(context); UNUSED_PARAM(addresses); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_append_name(
  struct getdns_context  *context,
  uint16_t               value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_suffix(
  struct getdns_context  *context,
  struct getdns_list     *value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_dnssec_trust_anchors(
  struct getdns_context  *context,
  struct getdns_list     *value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_dnssec_allowed_skew(
  struct getdns_context  *context,
  uint16_t               value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_upstream_recursive_servers(
  struct getdns_context  *context,
  struct getdns_list     *upstream_list
)
{ UNUSED_PARAM(context); UNUSED_PARAM(upstream_list); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_edns_maximum_udp_payload_size(
  struct getdns_context  *context,
  uint16_t               value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_edns_extended_rcode(
  struct getdns_context  *context,
  uint8_t                value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_edns_version(
  struct getdns_context  *context,
  uint8_t                value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_edns_do_bit(
  struct getdns_context  *context,
  uint8_t                value
)
{ UNUSED_PARAM(context); UNUSED_PARAM(value); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_memory_functions(
  struct getdns_context *context,
  void                  *(*malloc) (size_t),
  void                  *(*realloc) (void *, size_t),
  void                  (*free) (void *)
)
{ UNUSED_PARAM(context); 
  UNUSED_PARAM(malloc); UNUSED_PARAM(realloc); UNUSED_PARAM(free);
  return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_context_set_extended_memory_functions(
  struct getdns_context *context,
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
    struct getdns_context  *context,
    struct event_base      *this_event_base
)
{ UNUSED_PARAM(context); UNUSED_PARAM(this_event_base); return GETDNS_RETURN_GOOD; }

