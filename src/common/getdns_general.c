/**
 *
 * /brief getdns core functions
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

#include <getdns_core_only.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

/*
 * getdns_general
 */
getdns_return_t
getdns_general(
  getdns_context_t           context,
  const char                 *name,
  uint16_t                   request_type,
  struct getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{
    UNUSED_PARAM(context);
    UNUSED_PARAM(name);
    UNUSED_PARAM(request_type);
    UNUSED_PARAM(extensions);
    UNUSED_PARAM(userarg);
    UNUSED_PARAM(transaction_id);
    UNUSED_PARAM(callback);
    return GETDNS_RETURN_GOOD;
} /* getdns_general */


/*
 * getdns_address
 *
 */
getdns_return_t
getdns_address(
  getdns_context_t           context,
  const char                 *name,
  struct getdns_dict         *extensions,
  void                       *userarg,
  getdns_transaction_t       *transaction_id,
  getdns_callback_t          callback
)
{
    int cleanup_extensions = 0;
    if (!extensions) {
        extensions = getdns_dict_create();
        cleanup_extensions = 1;
    }
    getdns_dict_set_int(extensions,
                        GETDNS_STR_EXTENSION_RETURN_BOTH_V4_AND_V6,
                        GETDNS_EXTENSION_TRUE);

    getdns_return_t result = 
        getdns_general(context, name, GETDNS_RRTYPE_A,
                       extensions, userarg, transaction_id,
                       callback);
    if (cleanup_extensions) {
        getdns_dict_destroy(extensions);
    }
    return result;
} 

/* getdns_general.c */
