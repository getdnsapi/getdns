/**
 *
 * \file general.h
 * @brief getdns_general and related support functions
 *
 * This is the meat of the API
 * Originally taken from the getdns API description pseudo implementation.
 *
 */
/*
 * Copyright (c) 2013, NLnet Labs, Verisign, Inc.
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

#ifndef _GETDNS_GENERAL_H_
#define _GETDNS_GENERAL_H_

#include "getdns/getdns.h"
#include "types-internal.h"

/* private inner helper used by sync and async */

void _getdns_call_user_callback(getdns_dns_req *, getdns_dict *);
void _getdns_check_dns_req_complete(getdns_dns_req *dns_req);

getdns_return_t
_getdns_general_loop(getdns_context *context, getdns_eventloop *loop,
    const char *name, uint16_t request_type, getdns_dict *extensions,
    void *userarg, getdns_dns_req **dnsreq,
    getdns_callback_t callbackfn, internal_cb_t internal_cb);

getdns_return_t
_getdns_address_loop(getdns_context *context, getdns_eventloop *loop,
    const char *name, getdns_dict *extensions,
    void *userarg, getdns_transaction_t *transaction_id,
    getdns_callback_t callbackfn);

getdns_return_t
_getdns_hostname_loop(getdns_context *context, getdns_eventloop *loop,
    getdns_dict *address, getdns_dict *extensions,
    void *userarg, getdns_transaction_t *transaction_id,
    getdns_callback_t callbackfn);

getdns_return_t
_getdns_service_loop(getdns_context *context, getdns_eventloop *loop,
    const char *name, getdns_dict *extensions,
    void *userarg, getdns_transaction_t *transaction_id,
    getdns_callback_t callbackfn);

#endif
