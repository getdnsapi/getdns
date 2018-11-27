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
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include "debug.h"
#include "context.h"

#include "tls.h"

static int _getdns_tls_verify_always_ok(int ok, X509_STORE_CTX *ctx)
{
# if defined(STUB_DEBUG) && STUB_DEBUG
	char	buf[8192];
	X509   *cert;
	int	 err;
	int	 depth;

	cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	if (cert)
		X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
	else
		strcpy(buf, "<unknown>");
	DEBUG_STUB("DEBUG Cert verify: depth=%d verify=%d err=%d subject=%s errorstr=%s\n", depth, ok, err, buf, X509_verify_cert_error_string(err));
# else /* defined(STUB_DEBUG) && STUB_DEBUG */
	(void)ok;
	(void)ctx;
# endif /* #else defined(STUB_DEBUG) && STUB_DEBUG */
	return 1;
}

static _getdns_tls_x509* _getdns_tls_x509_new(struct mem_funcs* mfs, X509* cert)
{
	_getdns_tls_x509* res;

	if (!cert)
		return NULL;

	res = GETDNS_MALLOC(*mfs, _getdns_tls_x509);
	if (res)
		res->ssl = cert;

	return res;
}

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
	OPENSSL_init_crypto( OPENSSL_INIT_ADD_ALL_CIPHERS
	                   | OPENSSL_INIT_ADD_ALL_DIGESTS
	                   | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
	(void)OPENSSL_init_ssl(0, NULL);
}

_getdns_tls_context* _getdns_tls_context_new(struct mem_funcs* mfs)
{
	_getdns_tls_context* res;

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_context)))
		return NULL;

	/* Create client context, use TLS v1.2 only for now */
#  ifdef HAVE_TLS_CLIENT_METHOD
	res->ssl = SSL_CTX_new(TLS_client_method());
#  else
	res->ssl = SSL_CTX_new(TLSv1_2_client_method());
#  endif
	if(res->ssl == NULL) {
		GETDNS_FREE(*mfs, res);
		return NULL;
	}
	return res;
}

getdns_return_t _getdns_tls_context_free(struct mem_funcs* mfs, _getdns_tls_context* ctx)
{
	if (!ctx || !ctx->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	SSL_CTX_free(ctx->ssl);
	GETDNS_FREE(*mfs, ctx);
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

_getdns_tls_connection* _getdns_tls_connection_new(struct mem_funcs* mfs, _getdns_tls_context* ctx, int fd)
{
	_getdns_tls_connection* res;

	if (!ctx || !ctx->ssl)
		return NULL;

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_connection)))
		return NULL;

	res->ssl = SSL_new(ctx->ssl);
	if (!res->ssl) {
		GETDNS_FREE(*mfs, res);
		return NULL;
	}

	if (!SSL_set_fd(res->ssl, fd)) {
		SSL_free(res->ssl);
		GETDNS_FREE(*mfs, res);
		return NULL;
	}

	/* Connection is a client. */
	SSL_set_connect_state(res->ssl);

	/* If non-application data received, retry read. */
	SSL_set_mode(res->ssl, SSL_MODE_AUTO_RETRY);
	return res;
}

getdns_return_t _getdns_tls_connection_free(struct mem_funcs* mfs, _getdns_tls_connection* conn)
{
	if (!conn || !conn->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	SSL_free(conn->ssl);
	GETDNS_FREE(*mfs, conn);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_shutdown(_getdns_tls_connection* conn)
{
	if (!conn || !conn->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;

	switch (SSL_shutdown(conn->ssl)) {
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

_getdns_tls_session* _getdns_tls_connection_get_session(struct mem_funcs* mfs, _getdns_tls_connection* conn)
{
	_getdns_tls_session* res;

	if (!conn || !conn->ssl)
		return NULL;

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_session)))
		return NULL;

	res->ssl = SSL_get1_session(conn->ssl);
	if (!res->ssl) {
		GETDNS_FREE(*mfs, res);
		return NULL;
	}

	return res;
}

const char* _getdns_tls_connection_get_version(_getdns_tls_connection* conn)
{
	if (!conn || !conn->ssl)
		return NULL;
	return SSL_get_version(conn->ssl);
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
	switch (err) {
	case SSL_ERROR_WANT_READ:
		return GETDNS_RETURN_TLS_WANT_READ;

	case SSL_ERROR_WANT_WRITE:
		return GETDNS_RETURN_TLS_WANT_WRITE;

	default:
		return GETDNS_RETURN_GENERIC_ERROR;
	}
}

_getdns_tls_x509* _getdns_tls_connection_get_peer_certificate(struct mem_funcs* mfs, _getdns_tls_connection* conn)
{
	if (!conn || !conn->ssl)
		return NULL;

	return _getdns_tls_x509_new(mfs, SSL_get_peer_certificate(conn->ssl));
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

getdns_return_t _getdns_tls_connection_setup_hostname_auth(_getdns_tls_connection* conn, const char* auth_name)
{
	if (!conn || !conn->ssl || !auth_name)
		return GETDNS_RETURN_INVALID_PARAMETER;

	SSL_set_tlsext_host_name(conn->ssl, auth_name);
	/* Set up native OpenSSL hostname verification */
	X509_VERIFY_PARAM *param;
	param = SSL_get0_param(conn->ssl);
	X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	X509_VERIFY_PARAM_set1_host(param, auth_name, 0);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_set_host_pinset(_getdns_tls_connection* conn, const char* auth_name, const sha256_pin_t* pinset)
{
	if (!conn || !conn->ssl || !auth_name)
		return GETDNS_RETURN_INVALID_PARAMETER;

	int osr = SSL_dane_enable(conn->ssl, *auth_name ? auth_name : NULL);
	(void) osr;
	DEBUG_STUB("%s %-35s: DEBUG: SSL_dane_enable(\"%s\") -> %d\n"
	          , STUB_DEBUG_SETUP_TLS, __FUNC__, upstream->tls_auth_name, osr);
	SSL_set_verify(conn->ssl, SSL_VERIFY_PEER, _getdns_tls_verify_always_ok);
	const sha256_pin_t *pin_p;
	size_t n_pins = 0;
	for (pin_p = pinset; pin_p; pin_p = pin_p->next) {
		osr = SSL_dane_tlsa_add(conn->ssl, 2, 1, 1,
		    (unsigned char *)pin_p->pin, SHA256_DIGEST_LENGTH);
		DEBUG_STUB("%s %-35s: DEBUG: SSL_dane_tlsa_add() -> %d\n"
			  , STUB_DEBUG_SETUP_TLS, __FUNC__, osr);
		if (osr > 0)
			++n_pins;
		osr = SSL_dane_tlsa_add(conn->ssl, 3, 1, 1,
		    (unsigned char *)pin_p->pin, SHA256_DIGEST_LENGTH);
		DEBUG_STUB("%s %-35s: DEBUG: SSL_dane_tlsa_add() -> %d\n"
			  , STUB_DEBUG_SETUP_TLS, __FUNC__, osr);
		if (osr > 0)
			++n_pins;
	}
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_verify(_getdns_tls_connection* conn, long* errnum, const char** errmsg)
{
	if (!conn || !conn->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;

	long verify_result = SSL_get_verify_result(conn->ssl);
	switch (verify_result) {
	case X509_V_OK:
		return GETDNS_RETURN_GOOD;

	case X509_V_ERR_DANE_NO_MATCH:
		if (errnum)
			*errnum = 0;
		if (errmsg)
			*errmsg = "Pinset validation failure";
		return GETDNS_RETURN_GENERIC_ERROR;

	default:
		if (errnum)
			*errnum = verify_result;
		if (errmsg)
			*errmsg = X509_verify_cert_error_string(verify_result);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
}


getdns_return_t _getdns_tls_connection_read(_getdns_tls_connection* conn, uint8_t* buf, size_t to_read, size_t* read)
{
	int sread;

	if (!conn || !conn->ssl || !read)
		return GETDNS_RETURN_INVALID_PARAMETER;

	ERR_clear_error();
	sread = SSL_read(conn->ssl, buf, to_read);
	if (sread <= 0) {
		switch (SSL_get_error(conn->ssl, sread)) {
		case SSL_ERROR_WANT_READ:
			return GETDNS_RETURN_TLS_WANT_READ;

		case SSL_ERROR_WANT_WRITE:
			return GETDNS_RETURN_TLS_WANT_WRITE;

		default:
			return GETDNS_RETURN_GENERIC_ERROR;
		}
	}

	*read = sread;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_write(_getdns_tls_connection* conn, uint8_t* buf, size_t to_write, size_t* written)
{
	int swritten;

	if (!conn || !conn->ssl || !written)
		return GETDNS_RETURN_INVALID_PARAMETER;

	ERR_clear_error();
	swritten = SSL_write(conn->ssl, buf, to_write);
	if (swritten <= 0) {
		switch(SSL_get_error(conn->ssl, swritten)) {
		case SSL_ERROR_WANT_READ:
			/* SSL_write will not do partial writes, because
			 * SSL_MODE_ENABLE_PARTIAL_WRITE is not default,
			 * but the write could fail because of renegotiation.
			 * In that case SSL_get_error()  will return
			 * SSL_ERROR_WANT_READ or, SSL_ERROR_WANT_WRITE.
			 * Return for retry in such cases.
			 */
			return GETDNS_RETURN_TLS_WANT_READ;

		case SSL_ERROR_WANT_WRITE:
			return GETDNS_RETURN_TLS_WANT_WRITE;

		default:
			return GETDNS_RETURN_GENERIC_ERROR;
		}
	}

	*written = swritten;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_session_free(struct mem_funcs* mfs, _getdns_tls_session* s)
{
	if (!s || !s->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	SSL_SESSION_free(s->ssl);
	GETDNS_FREE(*mfs, s);
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

void _getdns_tls_x509_free(struct mem_funcs* mfs, _getdns_tls_x509* cert)
{
	if (cert && cert->ssl)
		X509_free(cert->ssl);
	GETDNS_FREE(*mfs, cert);
}

int _getdns_tls_x509_to_der(struct mem_funcs* mfs, _getdns_tls_x509* cert, getdns_bindata* bindata)
{
	unsigned char* buf = NULL;
	int len;

	if (!cert || !cert->ssl )
		return 0;

	if (bindata == NULL)
		return i2d_X509(cert->ssl, NULL);

	len = i2d_X509(cert->ssl, &buf);
	if (len == 0 || (bindata->data = GETDNS_XMALLOC(*mfs, uint8_t, len)) == NULL) {
		bindata->size = 0;
		bindata->data = NULL;
	} else {
		bindata->size = len;
		(void) memcpy(bindata->data, buf, len);
		OPENSSL_free(buf);
	}

	return len;
}

unsigned char* _getdns_tls_hmac_hash(struct mem_funcs* mfs, int algorithm, const void* key, size_t key_size, const void* data, size_t data_size, size_t* output_size)
{
	const EVP_MD* digester;
	unsigned char* res;
	unsigned int md_len;

	switch (algorithm) {
#ifdef HAVE_EVP_MD5
	case GETDNS_HMAC_MD5   : digester = EVP_md5()   ; break;
#endif
#ifdef HAVE_EVP_SHA1
	case GETDNS_HMAC_SHA1  : digester = EVP_sha1()  ; break;
#endif
#ifdef HAVE_EVP_SHA224
	case GETDNS_HMAC_SHA224: digester = EVP_sha224(); break;
#endif
#ifdef HAVE_EVP_SHA256
	case GETDNS_HMAC_SHA256: digester = EVP_sha256(); break;
#endif
#ifdef HAVE_EVP_SHA384
	case GETDNS_HMAC_SHA384: digester = EVP_sha384(); break;
#endif
#ifdef HAVE_EVP_SHA512
	case GETDNS_HMAC_SHA512: digester = EVP_sha512(); break;
#endif
	default                : return NULL;
	}

	res = (unsigned char*) GETDNS_XMALLOC(*mfs, unsigned char, EVP_MAX_MD_SIZE);
	if (!res)
		return NULL;

	(void) HMAC(digester, key, key_size, data, data_size, res, &md_len);

	if (output_size)
		*output_size = md_len;
	return res;
}

_getdns_tls_hmac* _getdns_tls_hmac_new(struct mem_funcs* mfs, int algorithm, const void* key, size_t key_size)
{
	const EVP_MD *digester;
	_getdns_tls_hmac* res;

	switch (algorithm) {
#ifdef HAVE_EVP_MD5
	case GETDNS_HMAC_MD5   : digester = EVP_md5()   ; break;
#endif
#ifdef HAVE_EVP_SHA1
	case GETDNS_HMAC_SHA1  : digester = EVP_sha1()  ; break;
#endif
#ifdef HAVE_EVP_SHA224
	case GETDNS_HMAC_SHA224: digester = EVP_sha224(); break;
#endif
#ifdef HAVE_EVP_SHA256
	case GETDNS_HMAC_SHA256: digester = EVP_sha256(); break;
#endif
#ifdef HAVE_EVP_SHA384
	case GETDNS_HMAC_SHA384: digester = EVP_sha384(); break;
#endif
#ifdef HAVE_EVP_SHA512
	case GETDNS_HMAC_SHA512: digester = EVP_sha512(); break;
#endif
	default                : return NULL;
	}

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_hmac)))
		return NULL;

#ifdef HAVE_HMAC_CTX_NEW
	res->ctx = HMAC_CTX_new();
	if (!res->ctx) {
		GETDNS_FREE(*mfs, res);
		return NULL;
	}
#else
	res->ctx = &res->ctx_space;
	HMAC_CTX_init(res->ctx);
#endif
	if (!HMAC_Init_ex(res->ctx, key, key_size, digester, NULL)) {
#ifdef HAVE_HMAC_CTX_NEW
		HMAC_CTX_free(res->ctx);
#endif
		GETDNS_FREE(*mfs, res);
		return NULL;
	}

	return res;
}

getdns_return_t _getdns_tls_hmac_add(_getdns_tls_hmac* h, const void* data, size_t data_size)
{
	if (!h || !h->ctx || !data)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!HMAC_Update(h->ctx, data, data_size))
		return GETDNS_RETURN_GENERIC_ERROR;
	else
		return GETDNS_RETURN_GOOD;
}

unsigned char* _getdns_tls_hmac_end(struct mem_funcs* mfs, _getdns_tls_hmac* h, size_t* output_size)
{
	unsigned char* res;
	unsigned int md_len;

	res = (unsigned char*) GETDNS_XMALLOC(*mfs, unsigned char, EVP_MAX_MD_SIZE);
	if (!res)
		return NULL;

	(void) HMAC_Final(h->ctx, res, &md_len);

#ifdef HAVE_HMAC_CTX_NEW
	HMAC_CTX_free(h->ctx);
#endif
	GETDNS_FREE(*mfs, h);

	if (output_size)
		*output_size = md_len;
	return res;
}

void _getdns_tls_sha1(const void* data, size_t data_size, unsigned char* buf)
{
	SHA1(data, data_size, buf);
}

/* tls.c */
