/**
 *
 * \file tls.h
 * @brief getdns TLS functions
 */

/*
 * Copyright (c) 2018, NLnet Labs
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

#ifndef _GETDNS_TLS_H
#define _GETDNS_TLS_H

#include "getdns/getdns.h"

#ifndef HAVE_DECL_SSL_CTX_SET1_CURVES_LIST
#define HAVE_TLS_CTX_CURVES_LIST	0
#else
#define HAVE_TLS_CTX_CURVES_LIST	(HAVE_DECL_SSL_CTX_SET1_CURVES_LIST)
#endif
#ifndef HAVE_DECL_SSL_SET1_CURVES_LIST
#define HAVE_TLS_CONN_CURVES_LIST	0
#else
#define HAVE_TLS_CONN_CURVES_LIST	(HAVE_DECL_SSL_SET1_CURVES_LIST)
#endif

typedef struct _getdns_tls_context {
	SSL_CTX* ssl;
} _getdns_tls_context;

typedef struct _getdns_tls_connection {
	SSL* ssl;
} _getdns_tls_connection;

typedef struct _getdns_tls_session {
	SSL_SESSION* ssl;
} _getdns_tls_session;

void _getdns_tls_init();

_getdns_tls_context* _getdns_tls_context_new();
getdns_return_t _getdns_tls_context_free(_getdns_tls_context* ctx);

getdns_return_t _getdns_tls_context_set_min_proto_1_2(_getdns_tls_context* ctx);
getdns_return_t _getdns_tls_context_set_cipher_list(_getdns_tls_context* ctx, const char* list);
getdns_return_t _getdns_tls_context_set_curves_list(_getdns_tls_context* ctx, const char* list);
getdns_return_t _getdns_tls_context_set_ca(_getdns_tls_context* ctx, const char* file, const char* path);

_getdns_tls_connection* _getdns_tls_connection_new(_getdns_tls_context* ctx, int fd);
getdns_return_t _getdns_tls_connection_free(_getdns_tls_connection* ctx);
getdns_return_t _getdns_tls_connection_shutdown(_getdns_tls_connection* conn);

getdns_return_t _getdns_tls_connection_set_cipher_list(_getdns_tls_connection* conn, const char* list);
getdns_return_t _getdns_tls_connection_set_curves_list(_getdns_tls_connection* conn, const char* list);
getdns_return_t _getdns_tls_connection_set_session(_getdns_tls_connection* conn, _getdns_tls_session* s);
_getdns_tls_session* _getdns_tls_connection_get_session(_getdns_tls_connection* conn);

getdns_return_t _getdns_tls_session_free(_getdns_tls_session* s);

getdns_return_t _getdns_tls_get_api_information(getdns_dict* dict);

#endif /* _GETDNS_TLS_H */
