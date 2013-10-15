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

/**
 * Much of this is based on / duplicated code from libevent evdns.  Credits to
 * Nick Mathewson and Niels Provos
 *
 * https://github.com/libevent/libevent/
 *
 * libevent dns is based on software by Adam Langly. Adam's original message:
 *
 * Async DNS Library
 * Adam Langley <agl@imperialviolet.org>
 * http://www.imperialviolet.org/eventdns.html
 * Public Domain code
 *
 * This software is Public Domain. To view a copy of the public domain dedication,
 * visit http://creativecommons.org/licenses/publicdomain/ or send a letter to
 * Creative Commons, 559 Nathan Abbott Way, Stanford, California 94305, USA.
 *
 * I ask and expect, but do not require, that all derivative works contain an
 * attribution similar to:
 *	Parts developed by Adam Langley <agl@imperialviolet.org>
 *
 * You may wish to replace the word "Parts" with something else depending on
 * the amount of original code.
 *
 * (Derivative works does not include programs which link against, run or include
 * the source verbatim in their source distributions)
 *
 * Version: 0.1b
 */

#include <string.h>
#include <unbound.h>
#include <unbound-event.h>
#include <ldns/ldns.h>
#include "context.h"
#include "util-internal.h"

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

typedef struct getdns_ub_req {
  struct ub_ctx *unbound;
  getdns_context_t context;
  char* name;
  void* userarg;
  getdns_callback_t callback;
  getdns_transaction_t transaction_id;
} getdns_ub_req;

static void getdns_ub_req_free(getdns_ub_req* req) {
  free(req->name);
  free(req);
}

void ub_resolve_callback(void* arg, int err, ldns_buffer* result, int sec, char* bogus) {
  getdns_ub_req* req = (getdns_ub_req*) arg;
  ldns_pkt* pkt = NULL;
  if (err) {
    req->callback(req->context,
                  GETDNS_CALLBACK_ERROR,
                  NULL, 
                  req->userarg,
                  req->transaction_id);
  } else {
    /* parse */
    ldns_status r = ldns_buffer2pkt_wire(&pkt, result);
    if (r != LDNS_STATUS_OK) {
      req->callback(req->context,
                    GETDNS_CALLBACK_ERROR,
                    NULL, 
                    req->userarg,
                    req->transaction_id);
    } else {
      getdns_dict* response = create_getdns_response(pkt);
      ldns_pkt_free(pkt);
      req->callback(req->context, 
                    GETDNS_CALLBACK_COMPLETE,
                    response, 
                    req->userarg,
                    req->transaction_id);
    }
  }
  /* cleanup */
  getdns_ub_req_free(req);
}

getdns_return_t
getdns_general_ub(
  struct ub_ctx*         unbound,
  getdns_context_t       context,
  const char             *name,
  uint16_t               request_type,
  struct getdns_dict     *extensions,
  void                   *userarg,
  getdns_transaction_t   *transaction_id,
  getdns_callback_t      callbackfn
) {

    int r;
    int async_id = 0;

    /* request state */
    getdns_ub_req* req = (getdns_ub_req*) malloc(sizeof(getdns_ub_req));
    req->unbound = unbound;
    req->context = context;
    req->name = strdup(name);
    req->userarg = userarg;
    req->callback = callbackfn;

    /* TODO: 
       setup root or stub 
       handle immediate callback
       A + AAAA
     */

    r = ub_resolve_event(unbound, req->name, request_type,
                         LDNS_RR_CLASS_IN, req, ub_resolve_callback,
                         &async_id);

    if (transaction_id) {
      *transaction_id = async_id;
    }
    req->transaction_id = async_id;


    if (r != 0) {
      getdns_ub_req_free(req);
      return GETDNS_RETURN_GENERIC_ERROR;
    }
    return GETDNS_RETURN_GOOD;
}

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
    
    if (!context || context->async_set == 0 ||
        callback == NULL) {
        /* Can't do async without an event loop
         * or callback        
         */
        return GETDNS_RETURN_BAD_CONTEXT;
    }
    
    return getdns_general_ub(context->unbound_async,
                             context,
                             name,
                             request_type,
                             extensions,
                             userarg,
                             transaction_id,
                             callback);

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
