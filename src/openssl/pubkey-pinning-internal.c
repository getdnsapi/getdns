/**
 *
 * /brief functions for Public Key Pinning
 *
 */

/*
 * Copyright (c) 2015, Daniel Kahn Gillmor
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

/**
 * getdns Public Key Pinning
 * 
 * a public key pinset is a list of dicts.  each dict should have a
 * "digest" and a "value".
 * 
 * "digest": a string indicating the type of digest. at the moment, we
 *           only support a "digest" of "sha256".
 * 
 * "value": a binary representation of the digest provided.
 * 
 * given a such a pinset, we should be able to validate a chain
 * properly according to section 2.6 of RFC 7469.
 */
#include "config.h"
#include "debug.h"
#include <getdns/getdns.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <string.h>
#include "context.h"
#include "util-internal.h"

#include "pubkey-pinning-internal.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000 || defined(HAVE_LIBRESSL)
#define X509_STORE_CTX_get0_untrusted(store) store->untrusted
#endif

/* we only support sha256 at the moment.  adding support for another
   digest is more complex than just adding another entry here. in
   particular, you'll probably need a match for a particular cert
   against all supported algorithms.  better to wait on doing that
   until it is a better-understood problem (i.e. wait until hpkp is
   updated and follow the guidance in rfc7469bis)
*/

/* b64 turns every 3 octets (or fraction thereof) into 4 octets */
#define B64_ENCODED_SHA256_LENGTH (((SHA256_DIGEST_LENGTH + 2)/3)  * 4)
getdns_return_t _getdns_decode_base64(const char* str, uint8_t* res, size_t res_size)
{
	BIO *bio = NULL;
	char inbuf[B64_ENCODED_SHA256_LENGTH + 1];
	getdns_return_t ret = GETDNS_RETURN_GOOD;

	/* openssl needs a trailing newline to base64 decode */
	memcpy(inbuf, str, B64_ENCODED_SHA256_LENGTH);
	inbuf[B64_ENCODED_SHA256_LENGTH] = '\n';
	
	bio = BIO_push(BIO_new(BIO_f_base64()),
		       BIO_new_mem_buf(inbuf, sizeof(inbuf)));
	if (BIO_read(bio, res, res_size) != (int) res_size)
		ret = GETDNS_RETURN_GENERIC_ERROR;

	BIO_free_all(bio);
	return ret;
}

/* this should only happen once ever in the life of the library. it's
   used to associate a getdns_context_t with an SSL_CTX, to be able to
   do custom verification.
   
   see doc/HOWTO/proxy_certificates.txt as an example
*/
static int
#if OPENSSL_VERSION_NUMBER < 0x10100000 || defined(HAVE_LIBRESSL)
_get_ssl_getdns_upstream_idx(void)
#else
_get_ssl_getdns_upstream_idx(X509_STORE *store)
#endif
{
	static volatile int idx = -1;
	if (idx < 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000 || defined(HAVE_LIBRESSL)
		CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);
#else
		X509_STORE_lock(store);
#endif
		if (idx < 0)
			idx = SSL_get_ex_new_index(0, "associated getdns upstream",
						   NULL,NULL,NULL);
#if OPENSSL_VERSION_NUMBER < 0x10100000 || defined(HAVE_LIBRESSL)
		CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
#else
		X509_STORE_unlock(store);
#endif
	}
	return idx;
}

getdns_upstream*
_getdns_upstream_from_x509_store(X509_STORE_CTX *store)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000 || defined(HAVE_LIBRESSL)
	int uidx = _get_ssl_getdns_upstream_idx();
#else
	int uidx = _get_ssl_getdns_upstream_idx(X509_STORE_CTX_get0_store(store));
#endif
	int sslidx = SSL_get_ex_data_X509_STORE_CTX_idx();
	const SSL *ssl;

	/* all *_get_ex_data() should return NULL on failure anyway */
	ssl = X509_STORE_CTX_get_ex_data(store, sslidx);
	if (ssl)
		return (getdns_upstream*) SSL_get_ex_data(ssl, uidx);
	else
		return NULL;
	/* TODO: if we want more details about errors somehow, we
	 * might call ERR_get_error (see CRYPTO_set_ex_data(3ssl))*/
}

getdns_return_t
_getdns_associate_upstream_with_connection(_getdns_tls_connection *conn,
					   getdns_upstream *upstream)
{
	if (!conn || !conn->ssl)
		return GETDNS_RETURN_INVALID_PARAMETER;
	
#if OPENSSL_VERSION_NUMBER < 0x10100000 || defined(HAVE_LIBRESSL)
	int uidx = _get_ssl_getdns_upstream_idx();
#else
	int uidx = _get_ssl_getdns_upstream_idx(SSL_CTX_get_cert_store(SSL_get_SSL_CTX(conn->ssl)));
#endif
	if (SSL_set_ex_data(conn->ssl, uidx, upstream))
		return GETDNS_RETURN_GOOD;
	else
		return GETDNS_RETURN_GENERIC_ERROR;
	/* TODO: if we want more details about errors somehow, we
	 * might call ERR_get_error (see CRYPTO_set_ex_data(3ssl))*/
}

getdns_return_t
_getdns_verify_pinset_match(const sha256_pin_t *pinset,
			    X509_STORE_CTX *store)
{
	getdns_return_t ret = GETDNS_RETURN_GENERIC_ERROR;
	X509 *x, *prev = NULL;
	int i, len;
	unsigned char raw[4096];
	unsigned char *next;
	unsigned char buf[sizeof(pinset->pin)];
	const sha256_pin_t *p;

	if (pinset == NULL || store == NULL)
		return GETDNS_RETURN_GENERIC_ERROR;
	
	/* start at the base of the chain (the end-entity cert) and
	 * make sure that some valid element of the chain does match
	 * the pinset. */

	/* Testing with OpenSSL 1.0.1e-1 on debian indicates that
	 * store->untrusted holds the chain offered by the server in
	 * the order that the server offers it.  If the server offers
	 * bogus certificates (that is, matching and valid certs that
	 * belong to private keys that the server does not control),
	 * the the verification will succeed (including this pinset
	 * check), but the handshake will fail outside of this
	 * verification. */

	/* TODO: how do we handle raw public keys? */

	for (i = 0; i < sk_X509_num(X509_STORE_CTX_get0_untrusted(store)); i++, prev = x) {

		x = sk_X509_value(X509_STORE_CTX_get0_untrusted(store), i);
#if defined(STUB_DEBUG) && STUB_DEBUG
		DEBUG_STUB("%s %-35s: Name of cert: %d ",
		           STUB_DEBUG_SETUP_TLS, __FUNC__, i);
		X509_NAME_print_ex_fp(stderr, X509_get_subject_name(x), 1, XN_FLAG_ONELINE);
		fprintf(stderr, "\n");
#endif
		if (i > 0) {
		/* we ensure that "prev" is signed by "x" */
			EVP_PKEY *pkey = X509_get_pubkey(x);
			int verified;
			if (!pkey) {
				DEBUG_STUB("%s %-35s: Could not get pubkey from cert %d (%p)\n",
					   STUB_DEBUG_SETUP_TLS, __FUNC__, i, (void*)x);
				return GETDNS_RETURN_GENERIC_ERROR;
			}
			verified = X509_verify(prev, pkey);
			EVP_PKEY_free(pkey);
			if (!verified) {
				DEBUG_STUB("%s %-35s: cert %d (%p) was not signed by cert %d\n",
					   STUB_DEBUG_SETUP_TLS, __FUNC__, i-1, (void*)prev, i);
				return GETDNS_RETURN_GENERIC_ERROR;
			}
		}

		/* digest the cert with sha256 */
		len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), NULL);
		if (len > (int)sizeof(raw)) {
			DEBUG_STUB("%s %-35s: Pubkey %d is larger than %"PRIsz" octets\n",
			           STUB_DEBUG_SETUP_TLS, __FUNC__, i, sizeof(raw));
			continue;
		}
		next = raw;
		i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &next);
		if (next - raw != len) {
			DEBUG_STUB("%s %-35s: Pubkey %d claimed it needed %d octets, really needed %"PRIsz"\n",
			           STUB_DEBUG_SETUP_TLS, __FUNC__, i, len, next - raw);
			continue;
		}
		SHA256(raw, len, buf);

		/* compare it */
		for (p = pinset; p; p = p->next)
			if (0 == memcmp(buf, p->pin, sizeof(p->pin))) {
				DEBUG_STUB("%s %-35s: Pubkey %d matched pin %p (%"PRIsz")\n",
					   STUB_DEBUG_SETUP_TLS, __FUNC__, i, (void*)p, sizeof(p->pin));
				return GETDNS_RETURN_GOOD;
			} else
				DEBUG_STUB("%s %-35s: Pubkey %d did not match pin %p\n",
					   STUB_DEBUG_SETUP_TLS, __FUNC__, i, (void*)p);
	}

	return ret;
}

/* pubkey-pinning.c */
