/**
 *
 * /brief getdns contect management functions
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

#include <getdns_libevent.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

/*
 * getdns_context_create
 *
 * call this to initialize the context that is used in other getdns calls
 */
getdns_return_t
getdns_context_create(
    getdns_context_t       *context,
    bool                   set_from_os
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(set_from_os);

    return GETDNS_RETURN_GOOD;
} /* getdns_context_create */

/*
 * getdns_context_destroy
 *
 * call this to dispose of resources associated with a context once you
 * are done with it
 */
void
getdns_context_destroy(
	getdns_context_t       context
)
{
    UNUSED_PARAM(context);
} /* getdns_context_destroy */

/*
 * getdns_context_set_context_update_callback
 *
 */
getdns_return_t
getdns_context_set_context_update_callback(
  getdns_context_t       context,
  void                   (*value)(getdns_context_t context, uint16_t changed_item)
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_context_update_callback */

/*
 * getdns_context_set_context_update
 *
 */
getdns_return_t
getdns_context_set_context_update(
  getdns_context_t       context,
  uint16_t               value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_context_update */

/*
 * getdns_context_set_resolution_type
 *
 */
getdns_return_t
getdns_context_set_resolution_type(
  getdns_context_t       context,
  uint16_t               value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_resolution_type */

/*
 * getdns_context_set_namespaces
 *
 */
getdns_return_t
getdns_context_set_namespaces(
  getdns_context_t       context,
  size_t                 namespace_count,
  uint16_t               *namespaces
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(namespace_count);
    UNUSED_PARAM(namespaces);

    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_namespaces */

/*
 * getdns_context_set_dns_transport
 *
 */
getdns_return_t
getdns_context_set_dns_transport(
  getdns_context_t       context,
  uint16_t               value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_dns_transport */

/*
 * getdns_context_set_limit_outstanding_queries
 *
 */
getdns_return_t
getdns_context_set_limit_outstanding_queries(
  getdns_context_t       context,
  uint16_t               limit
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(limit);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_limit_outstanding_queries */

/*
 * getdns_context_set_timeout
 *
 */
getdns_return_t
getdns_context_set_timeout(
  getdns_context_t       context,
  uint16_t               timeout
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(timeout);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_timeout */

/*
 * getdns_context_set_follow_redirects
 *
 */
getdns_return_t
getdns_context_set_follow_redirects(
  getdns_context_t       context,
  uint16_t               value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_follow_redirects */

/*
 * getdns_context_set_dns_root_servers
 *
 */
getdns_return_t
getdns_context_set_dns_root_servers(
  getdns_context_t       context,
  struct getdns_list     *addresses
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(addresses);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_dns_root_servers */

/*
 * getdns_context_set_append_name
 *
 */
getdns_return_t
getdns_context_set_append_name(
  getdns_context_t       context,
  uint16_t               value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_append_name */

/*
 * getdns_context_set_suffix
 *
 */
getdns_return_t
getdns_context_set_suffix(
  getdns_context_t       context,
  struct getdns_list     *value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_suffix */

/*
 * getdns_context_set_dnssec_trust_anchors
 *
 */
getdns_return_t
getdns_context_set_dnssec_trust_anchors(
  getdns_context_t       context,
  struct getdns_list     *value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_dnssec_trust_anchors */

/*
 * getdns_context_set_dnssec_allowed_skew
 *
 */
getdns_return_t
getdns_context_set_dnssec_allowed_skew(
  getdns_context_t       context,
  uint16_t               value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_dnssec_allowed_skew */

/*
 * getdns_context_set_stub_resolution
 *
 */
getdns_return_t
getdns_context_set_stub_resolution(
  getdns_context_t       context,
  struct getdns_list     *upstream_list
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(upstream_list);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_stub_resolution */

/*
 * getdns_context_set_edns_maximum_udp_payload_size
 *
 */
getdns_return_t
getdns_context_set_edns_maximum_udp_payload_size(
  getdns_context_t       context,
  uint16_t               value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_edns_maximum_udp_payload_size */

/*
 * getdns_context_set_edns_extended_rcode
 *
 */
getdns_return_t
getdns_context_set_edns_extended_rcode(
  getdns_context_t       context,
  uint8_t                value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_edns_extended_rcode */

/*
 * getdns_context_set_edns_version
 *
 */
getdns_return_t
getdns_context_set_edns_version(
  getdns_context_t       context,
  uint8_t                value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_edns_version */

/*
 * getdns_context_set_edns_do_bit
 *
 */
getdns_return_t
getdns_context_set_edns_do_bit(
  getdns_context_t       context,
  uint8_t                value
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_edns_do_bit */

/*
 * getdns_context_set_memory_allocator
 *
 */
getdns_return_t
getdns_context_set_memory_allocator(
  getdns_context_t       context,
  void                   (*value)(size_t somesize)
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_memory_allocator */

/*
 * getdns_context_set_memory_deallocator
 *
 */
getdns_return_t
getdns_context_set_memory_deallocator(
  getdns_context_t       context,
  void                   (*value)(void*)
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_memory_deallocator */

/*
 * getdns_context_set_memory_reallocator
 *
 */
getdns_return_t
getdns_context_set_memory_reallocator(
  getdns_context_t       context,
  void                   (*value)(void*)
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(value);
    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_memory_reallocator */

/*
 * getdns_extension_set_libevent_base
 *
 */
getdns_return_t
getdns_extension_set_libevent_base(
    getdns_context_t       context,
    struct event_base      *this_event_base
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(this_event_base);
    return GETDNS_RETURN_GOOD;
} /* getdns_extension_set_libevent_base */

/* getdns_context.c */
