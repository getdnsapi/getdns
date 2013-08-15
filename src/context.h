/**
 * TODO: proper header
 */

#ifndef _GETDNS_CONTEXT_H_
#define _GETDNS_CONTEXT_H_

#include <getdns/getdns.h>

/** function pointer typedefs */
typedef void (*getdns_update_callback)(getdns_context_t context, uint16_t changed_item);
typedef void* (*getdns_memory_allocator)(size_t size);
typedef void (*getdns_memory_deallocator)(void*);
typedef void* (*getdns_memory_reallocator)(void* ptr, size_t size);

struct getdns_context_t {

    /* Context values */
    uint16_t resolution_type;
    uint16_t *namespaces;
    uint16_t dns_transport;
    uint16_t limit_outstanding_queries;
    uint16_t timeout;
    uint16_t follow_redirects;
    struct getdns_list *dns_root_servers;
    uint16_t append_name;
    struct getdns_list *suffix;
    struct getdns_list *dnssec_trust_anchors;
    uint16_t dnssec_allow_skew;
    struct getdns_list *upstream_list;
    uint16_t edns_maximum_udp_payload_size;
    uint8_t edns_extended_rcode;
    uint8_t edns_version;
    uint8_t edns_do_bit;
    
    getdns_update_callback update_callback;
    getdns_memory_allocator memory_allocator;
    getdns_memory_deallocator memory_deallocator;
    getdns_memory_reallocator memory_reallocator;

    /* Event loop */
    struct event_base* event_base;
    
    /* outbound request dict (transaction -> req struct) */
    getdns_dict *outbound_reqs;

    /* socket */
    evutil_socket_t resolver_socket;
} ;

#endif

