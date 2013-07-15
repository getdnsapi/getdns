/**
 *
 * /brief getdns core functions for synchronous use
 * 
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


getdns_return_t
getdns_general_sync(
  getdns_context_t       context,
  const char             *name,
  uint16_t               request_type,
  struct getdns_dict     *extensions,
  uint32_t               *response_length,
  struct getdns_dict     *response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(request_type); UNUSED_PARAM(extensions);
UNUSED_PARAM(response_length); UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_address_sync(
  getdns_context_t       context,
  const char             *name,
  struct getdns_dict     *extensions,
  uint32_t               *response_length,
  struct getdns_dict     *response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(extensions);
UNUSED_PARAM(response_length); UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_hostname_sync(
  getdns_context_t       context,
  struct getdns_dict     *address,
  struct getdns_dict     *extensions,
  uint32_t               *response_length,
  struct getdns_dict     *response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(address); UNUSED_PARAM(extensions);
UNUSED_PARAM(response_length); UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

getdns_return_t
getdns_service_sync(
  getdns_context_t       context,
  const char             *name,
  struct getdns_dict     *extensions,
  uint32_t               *response_length,
  struct getdns_dict     *response
)
{ UNUSED_PARAM(context); UNUSED_PARAM(name); UNUSED_PARAM(extensions);
UNUSED_PARAM(response_length); UNUSED_PARAM(response); return GETDNS_RETURN_GOOD; }

void
getdns_free_sync_request_memory(
  struct getdns_dict     *response
)
{ UNUSED_PARAM(response); }

/* getdns_core_sync.c */
