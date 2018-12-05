/**
 *
 * \file tls-internal.h
 * @brief getdns TLS implementation-specific items
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

#ifndef _GETDNS_TLS_INTERNAL_H
#define _GETDNS_TLS_INTERNAL_H

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "getdns/getdns.h"

#define SHA_DIGEST_LENGTH	20
#define SHA224_DIGEST_LENGTH	28
#define SHA256_DIGEST_LENGTH	32
#define SHA384_DIGEST_LENGTH	48
#define SHA512_DIGEST_LENGTH	64

#define GETDNS_TLS_MAX_DIGEST_LENGTH	(SHA512_DIGEST_LENGTH)

#define HAVE_TLS_CTX_CURVES_LIST	0
#define HAVE_TLS_CONN_CURVES_LIST	0


typedef struct _getdns_tls_context {
	int unused;
} _getdns_tls_context;

typedef struct _getdns_tls_connection {
	gnutls_session_t tls;
	gnutls_certificate_credentials_t cred;
	int shutdown;
} _getdns_tls_connection;

typedef struct _getdns_tls_session {
	gnutls_datum_t tls;
} _getdns_tls_session;

typedef struct _getdns_tls_x509
{
	gnutls_datum_t tls;
} _getdns_tls_x509;

typedef struct _getdns_tls_hmac
{
	gnutls_hmac_hd_t tls;
	unsigned int md_len;
} _getdns_tls_hmac;

#endif /* _GETDNS_TLS_INTERNAL_H */
