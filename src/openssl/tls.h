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

/* Additional return codes required by TLS abstraction. Internal use only. */
#define GETDNS_RETURN_TLS_WANT_READ		((getdns_return_t) 420)
#define GETDNS_RETURN_TLS_WANT_WRITE		((getdns_return_t) 421)
#define GETDNS_RETURN_TLS_CONNECTION_FRESH	((getdns_return_t) 422)

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

/**
 * Report the TLS version of the connection.
 *
 * @param conn	the connection.
 * @return string with the connection description, NULL on error.
 */
const char* _getdns_tls_connection_get_version(_getdns_tls_connection* conn);

/**
 * Attempt TLS handshake.
 *
 * @param conn	the connection.
 * @return GETDNS_RETURN_GOOD if handshake is complete.
 * @return GETDNS_RETURN_INVALID_PARAMETER if conn is null or has no SSL.
 * @return GETDNS_RETURN_TLS_WANT_READ if handshake needs to read to proceed.
 * @return GETDNS_RETURN_TLS_WANT_WRITE if handshake needs to write to proceed.
 * @return GETDNS_RETURN_GENERIC_ERROR if handshake failed.
 */
getdns_return_t _getdns_tls_connection_do_handshake(_getdns_tls_connection* conn);

/**
 * See whether the connection is reusing a session.
 *
 * @param conn	the connection.
 * @return GETDNS_RETURN_GOOD if connection is being reused.
 * @return GETDNS_RETURN_INVALID_PARAMETER if conn is null or has no SSL.
 * @return GETDNS_RETURN_TLS_CONNECTION_FRESH if connection is not being reused.
 */
getdns_return_t _getdns_tls_connection_is_session_reused(_getdns_tls_connection* conn);

/**
 * Read from TLS.
 *
 * @param conn	  the connection.
 * @param buf	  the buffer to read to.
 * @param to_read the number of bytes to read.
 * @param read	  pointer to holder for the number of bytes read.
 * @return GETDNS_RETURN_GOOD if some bytes were read.
 * @return GETDNS_RETURN_INVALID_PARAMETER if conn is null or has no SSL.
 * @return GETDNS_RETURN_TLS_WANT_READ if the read needs to be retried.
 * @return GETDNS_RETURN_TLS_WANT_WRITE if handshake isn't finished.
 * @return GETDNS_RETURN_GENERIC_ERROR if read failed.
 */
getdns_return_t _getdns_tls_connection_read(_getdns_tls_connection* conn, uint8_t* buf, size_t to_read, size_t* read);

/**
 * Write to TLS.
 *
 * @param conn	   the connection.
 * @param buf	   the buffer to write from.
 * @param to_write the number of bytes to write.
 * @param written  the number of bytes written.
 * @return GETDNS_RETURN_GOOD if some bytes were read.
 * @return GETDNS_RETURN_INVALID_PARAMETER if conn is null or has no SSL.
 * @return GETDNS_RETURN_TLS_WANT_READ if handshake isn't finished.
 * @return GETDNS_RETURN_TLS_WANT_WRITE if the write needs to be retried.
 * @return GETDNS_RETURN_GENERIC_ERROR if write failed.
 */
getdns_return_t _getdns_tls_connection_write(_getdns_tls_connection* conn, uint8_t* buf, size_t to_write, size_t* written);

getdns_return_t _getdns_tls_session_free(_getdns_tls_session* s);

getdns_return_t _getdns_tls_get_api_information(getdns_dict* dict);

#endif /* _GETDNS_TLS_H */
