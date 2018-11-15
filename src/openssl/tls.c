/**
 *
 * \file tls.c
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

#include "config.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include "tls.h"

#ifdef USE_DANESSL
# include "ssl_dane/danessl.h"
#endif

#ifdef USE_WINSOCK
/* For windows, the CA trust store is not read by openssl.
   Add code to open the trust store using wincrypt API and add
   the root certs into openssl trust store */
static int
add_WIN_cacerts_to_openssl_store(SSL_CTX* tls_ctx)
{
	HCERTSTORE      hSystemStore;
	PCCERT_CONTEXT  pTargetCert = NULL;

	DEBUG_STUB("%s %-35s: %s\n", STUB_DEBUG_SETUP_TLS, __FUNC__,
		"Adding Windows certificates from system root store to CA store");

	/* load just once per context lifetime for this version of getdns
	   TODO: dynamically update CA trust changes as they are available */
	if (!tls_ctx)
		return 0;

	/* Call wincrypt's CertOpenStore to open the CA root store. */

	if ((hSystemStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		0,
		/* NOTE: mingw does not have this const: replace with 1 << 16 from code
		   CERT_SYSTEM_STORE_CURRENT_USER, */
		1 << 16,
		L"root")) == 0)
	{
		return 0;
	}

	X509_STORE* store = SSL_CTX_get_cert_store(tls_ctx);
	if (!store)
		return 0;

	/* failure if the CA store is empty or the call fails */
	if ((pTargetCert = CertEnumCertificatesInStore(
		hSystemStore, pTargetCert)) == 0) {
		DEBUG_STUB("%s %-35s: %s\n", STUB_DEBUG_SETUP_TLS, __FUNC__,
			"CA certificate store for Windows is empty.");
			return 0;
	}
	/* iterate over the windows cert store and add to openssl store */
	do
	{
		X509 *cert1 = d2i_X509(NULL,
			(const unsigned char **)&pTargetCert->pbCertEncoded,
			pTargetCert->cbCertEncoded);
		if (!cert1) {
			/* return error if a cert fails */
			DEBUG_STUB("%s %-35s: %s %d:%s\n", STUB_DEBUG_SETUP_TLS, __FUNC__,
				"Unable to parse certificate in memory",
				ERR_get_error(), ERR_error_string(ERR_get_error(), NULL));
			return 0;
		}
		else {
			/* return error if a cert add to store fails */
			if (X509_STORE_add_cert(store, cert1) == 0) {
				unsigned long error = ERR_peek_last_error();

				/* Ignore error X509_R_CERT_ALREADY_IN_HASH_TABLE which means the
				* certificate is already in the store.  */
				if(ERR_GET_LIB(error) != ERR_LIB_X509 ||
				   ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
					DEBUG_STUB("%s %-35s: %s %d:%s\n", STUB_DEBUG_SETUP_TLS, __FUNC__,
					    "Error adding certificate", ERR_get_error(),
					     ERR_error_string(ERR_get_error(), NULL));
					X509_free(cert1);
					return 0;
				}
			}
			X509_free(cert1);
		}
	} while ((pTargetCert = CertEnumCertificatesInStore(
		hSystemStore, pTargetCert)) != 0);

	/* Clean up memory and quit. */
	if (pTargetCert)
		CertFreeCertificateContext(pTargetCert);
	if (hSystemStore)
	{
		if (!CertCloseStore(
			hSystemStore, 0))
			return 0;
	}
	DEBUG_STUB("%s %-35s: %s\n", STUB_DEBUG_SETUP_TLS, __FUNC__,
		"Completed adding Windows certificates to CA store successfully");
	return 1;
}
#endif

void _getdns_tls_init()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000 || defined(HAVE_LIBRESSL)
	OpenSSL_add_all_algorithms();
	SSL_library_init();

# ifdef USE_DANESSL
		(void) DANESSL_library_init();
# endif
#else
	OPENSSL_init_crypto( OPENSSL_INIT_ADD_ALL_CIPHERS
	                   | OPENSSL_INIT_ADD_ALL_DIGESTS
	                   | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
	(void)OPENSSL_init_ssl(0, NULL);
#endif
}

_getdns_tls_context* _getdns_tls_context_new()
{
	_getdns_tls_context* res;

	if (!(res = malloc(sizeof(struct _getdns_tls_context))))
		return NULL;

	/* Create client context, use TLS v1.2 only for now */
#  ifdef HAVE_TLS_CLIENT_METHOD
	res->ssl = SSL_CTX_new(TLS_client_method());
#  else
	res->ssl = SSL_CTX_new(TLSv1_2_client_method());
#  endif
	if(res->ssl == NULL) {
		free(res);
		return NULL;
	}
	return res;
}

getdns_return_t _getdns_tls_context_free(_getdns_tls_context* ctx)
{
	if (!ctx || !ctx->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	SSL_CTX_free(ctx->ssl);
	free(ctx);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_context_set_min_proto_1_2(_getdns_tls_context* ctx)
{
#ifdef HAVE_SSL_CTX_SET_MIN_PROTO_VERSION
	if (!ctx || !ctx->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	if (!SSL_CTX_set_min_proto_version(ctx->ssl, TLS1_2_VERSION))
		return GETDNS_RETURN_BAD_CONTEXT;
	return GETDNS_RETURN_GOOD;
#else
	(void) ctx;
	return GETDNS_RETURN_NOT_IMPLEMENTED;
#endif
}

getdns_return_t _getdns_tls_context_set_cipher_list(_getdns_tls_context* ctx, const char* list)
{
	if (!ctx || !ctx->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	if (!SSL_CTX_set_cipher_list(ctx->ssl, list))
		return GETDNS_RETURN_BAD_CONTEXT;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_context_set_curves_list(_getdns_tls_context* ctx, const char* list)
{
	if (!ctx || !ctx->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
#if HAVE_TLS_CTX_CURVES_LIST
	if (list &&
	    !SSL_CTX_set1_curves_list(ctx->ssl, list))
		return GETDNS_RETURN_BAD_CONTEXT;
#else
	(void) list;
#endif
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_context_set_ca(_getdns_tls_context* ctx, const char* file, const char* path)
{
	if (!ctx || !ctx->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	if ((file || path) &&
	    SSL_CTX_load_verify_locations(ctx->ssl, file, path))
		return GETDNS_RETURN_GOOD; /* pass */
#ifndef USE_WINSOCK
	else if (SSL_CTX_set_default_verify_paths(ctx->ssl))
		return GETDNS_RETURN_GOOD;
#else
	else if (add_WIN_cacerts_to_openssl_store(ctx->ssl))
		return GETDNS_RETURN_GOOD;
#endif /* USE_WINSOCK */
	return GETDNS_RETURN_GENERIC_ERROR;
}

_getdns_tls_connection* _getdns_tls_connection_new(_getdns_tls_context* ctx, int fd)
{
	_getdns_tls_connection* res;

	if (!ctx || !ctx->ssl)
		return NULL;

	if (!(res = malloc(sizeof(struct _getdns_tls_connection))))
		return NULL;

	res->ssl = SSL_new(ctx->ssl);
	if (!res->ssl) {
		free(res);
		return NULL;
	}

	if (!SSL_set_fd(res->ssl, fd)) {
		SSL_free(res->ssl);
		free(res);
		return NULL;
	}

	/* Connection is a client. */
	SSL_set_connect_state(res->ssl);

	/* If non-application data received, retry read. */
	SSL_set_mode(res->ssl, SSL_MODE_AUTO_RETRY);
	return res;
}

getdns_return_t _getdns_tls_connection_free(_getdns_tls_connection* conn)
{
	if (!conn || !conn->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	SSL_free(conn->ssl);
	free(conn);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_shutdown(_getdns_tls_connection* conn)
{
	if (!conn || !conn->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;

	switch(SSL_shutdown(conn->ssl))
	{
	case 0:		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	case 1:		return GETDNS_RETURN_GOOD;
	default:	return GETDNS_RETURN_GENERIC_ERROR;
	}
}

getdns_return_t _getdns_tls_connection_set_cipher_list(_getdns_tls_connection* conn, const char* list)
{
	if (!conn || !conn->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	if (!SSL_set_cipher_list(conn->ssl, list))
		return GETDNS_RETURN_BAD_CONTEXT;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_set_curves_list(_getdns_tls_connection* conn, const char* list)
{
	if (!conn || !conn->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
#if HAVE_TLS_CONN_CURVES_LIST
	if (list &&
	    !SSL_set1_curves_list(conn->ssl, list))
		return GETDNS_RETURN_BAD_CONTEXT;
#else
	(void) list;
#endif
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_set_session(_getdns_tls_connection* conn, _getdns_tls_session* s)
{
	if (!conn || !conn->ssl || !s || !s->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	if (!SSL_set_session(conn->ssl, s->ssl))
		return GETDNS_RETURN_GENERIC_ERROR;
	return GETDNS_RETURN_GOOD;
}

_getdns_tls_session* _getdns_tls_connection_get_session(_getdns_tls_connection* conn)
{
	_getdns_tls_session* res;

	if (!conn || !conn->ssl)
		return NULL;

	if (!(res = malloc(sizeof(struct _getdns_tls_session))))
		return NULL;

	res->ssl = SSL_get1_session(conn->ssl);
	if (!res->ssl) {
		free(res);
		return NULL;
	}

	return res;
}

getdns_return_t _getdns_tls_connection_do_handshake(_getdns_tls_connection* conn)
{
	int r;
	int err;

	if (!conn || !conn->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;

	ERR_clear_error();
	r = SSL_do_handshake(conn->ssl);
	if (r == 1)
		return GETDNS_RETURN_GOOD;
	err = SSL_get_error(conn->ssl, r);
	switch(err)
	{
	case SSL_ERROR_WANT_READ:
		return GETDNS_RETURN_TLS_WANT_READ;

	case SSL_ERROR_WANT_WRITE:
		return GETDNS_RETURN_TLS_WANT_WRITE;

	default:
		return GETDNS_RETURN_GENERIC_ERROR;
	}
}

getdns_return_t _getdns_tls_connection_is_session_reused(_getdns_tls_connection* conn)
{
	if (!conn || !conn->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (SSL_session_reused(conn->ssl))
		return GETDNS_RETURN_GOOD;
	else
		return GETDNS_RETURN_TLS_CONNECTION_FRESH;
}

getdns_return_t _getdns_tls_session_free(_getdns_tls_session* s)
{
	if (!s || !s->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	SSL_SESSION_free(s->ssl);
	free(s);
	return GETDNS_RETURN_GOOD;
}



getdns_return_t _getdns_tls_get_api_information(getdns_dict* dict)
{
	if (! getdns_dict_set_int(
	    dict, "openssl_build_version_number", OPENSSL_VERSION_NUMBER)

#ifdef HAVE_OPENSSL_VERSION_NUM
	    && ! getdns_dict_set_int(
	    dict, "openssl_version_number", OpenSSL_version_num())
#endif
#ifdef HAVE_OPENSSL_VERSION
	    && ! getdns_dict_util_set_string(
	    dict, "openssl_version_string", OpenSSL_version(OPENSSL_VERSION))

	    && ! getdns_dict_util_set_string(
	    dict, "openssl_cflags", OpenSSL_version(OPENSSL_CFLAGS))

	    && ! getdns_dict_util_set_string(
	    dict, "openssl_built_on", OpenSSL_version(OPENSSL_BUILT_ON))

	    && ! getdns_dict_util_set_string(
	    dict, "openssl_platform", OpenSSL_version(OPENSSL_PLATFORM))

	    && ! getdns_dict_util_set_string(
	    dict, "openssl_dir", OpenSSL_version(OPENSSL_DIR))

	    && ! getdns_dict_util_set_string(
		    dict, "openssl_engines_dir", OpenSSL_version(OPENSSL_ENGINES_DIR))
#endif
		)
		return GETDNS_RETURN_GOOD;
	return GETDNS_RETURN_GENERIC_ERROR;
}

/* tls.c */
