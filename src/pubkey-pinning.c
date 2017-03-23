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

static const getdns_bindata sha256 = {
	.size = sizeof("sha256") - 1,
	.data = (uint8_t*)"sha256"
};
  

#define PIN_PREFIX "pin-sha256=\""
#define PIN_PREFIX_LENGTH (sizeof(PIN_PREFIX) - 1)
/* b64 turns every 3 octets (or fraction thereof) into 4 octets */
#define B64_ENCODED_SHA256_LENGTH (((SHA256_DIGEST_LENGTH + 2)/3)  * 4)

/* convert an HPKP-style pin description to an appropriate getdns data
   structure.  An example string is: (with the quotes, without any
   leading or trailing whitespace):

      pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="

   getdns_build_pin_from_string returns a dict created from ctx, or
   NULL if the string did not match.  If ctx is NULL, the dict is
   created via getdns_dict_create().

   It is the caller's responsibility to call getdns_dict_destroy when
   it is no longer needed.
 */
getdns_dict* getdns_pubkey_pin_create_from_string(
	getdns_context* context,
	const char* str)
{
	BIO *bio = NULL;
	size_t i;
	uint8_t buf[SHA256_DIGEST_LENGTH];
	char inbuf[B64_ENCODED_SHA256_LENGTH + 1];
	getdns_bindata value = { .size = SHA256_DIGEST_LENGTH, .data = buf };
	getdns_dict* out = NULL;
	
	/* we only do sha256 right now, make sure this is well-formed */
	if (!str || strncmp(PIN_PREFIX, str, PIN_PREFIX_LENGTH))
		return NULL;
	for (i = PIN_PREFIX_LENGTH; i < PIN_PREFIX_LENGTH + B64_ENCODED_SHA256_LENGTH - 1; i++)
		if (!((str[i] >= 'a' && str[i] <= 'z') ||
		      (str[i] >= 'A' && str[i] <= 'Z') ||
		      (str[i] >= '0' && str[i] <= '9') ||
		      (str[i] == '+') || (str[i] == '/')))
			return NULL;
	if (str[i++] != '=')
		return NULL;
	if (str[i++] != '"')
		return NULL;
	if (str[i++] != '\0')
		return NULL;

	/* openssl needs a trailing newline to base64 decode */
	memcpy(inbuf, str + PIN_PREFIX_LENGTH, B64_ENCODED_SHA256_LENGTH);
	inbuf[B64_ENCODED_SHA256_LENGTH] = '\n';
	
	bio = BIO_push(BIO_new(BIO_f_base64()),
		       BIO_new_mem_buf(inbuf, sizeof(inbuf)));
	if (BIO_read(bio, buf, sizeof(buf)) != sizeof(buf))
		goto fail;
	
	if (context)
		out = getdns_dict_create_with_context(context);
	else
		out = getdns_dict_create();
	if (out == NULL)
		goto fail;
	if (getdns_dict_set_bindata(out, "digest", &sha256))
		goto fail;
	if (getdns_dict_set_bindata(out, "value", &value))
		goto fail;
	return out;

 fail:
	BIO_free_all(bio);
	getdns_dict_destroy(out);
	return NULL;
}


/* Test whether a given pinset is reasonable, including:

 * is it well-formed?
 * are there at least two pins?
 * are the digests used sane?

   if errorlist is NULL, the sanity check just returns success or
   failure.

   if errorlist is not NULL, we append human-readable strings to
   report the errors.
*/

#define PKP_SC_ERR(e) { \
       if (errorlist) \
	       _getdns_list_append_const_bindata(errorlist, \
				       sizeof(e), e); \
       errorcount++; \
	}
#define PKP_SC_HARDERR(e, val) { \
		PKP_SC_ERR(e); return val; \
	}
getdns_return_t getdns_pubkey_pinset_sanity_check(
	const getdns_list* pinset,
	getdns_list* errorlist)
{
	size_t errorcount = 0, pins = 0, i;
	getdns_dict * pin;
	getdns_bindata * data;

	if (getdns_list_get_length(pinset, &pins))
		PKP_SC_HARDERR("Can't get length of pinset",
			       GETDNS_RETURN_INVALID_PARAMETER);
	if (pins < 2)
		PKP_SC_ERR("This pinset has fewer than 2 pins");
	for (i = 0; i < pins; i++)
	{
		/* is it a dict? */
		if (getdns_list_get_dict(pinset, i, &pin)) {
			PKP_SC_ERR("Could not retrieve a pin");
		} else {
		/* does the pin have the right digest type? */
			if (getdns_dict_get_bindata(pin, "digest", &data)) {
				PKP_SC_ERR("Pin has no 'digest' entry");
			} else {
				if (data->size != sha256.size ||
				    memcmp(data->data, sha256.data, sha256.size))
					PKP_SC_ERR("Pin has 'digest' other than sha256");
			}
			/* if it does, is the value the right length? */
			if (getdns_dict_get_bindata(pin, "value", &data)) {
				PKP_SC_ERR("Pin has no 'value' entry");
			} else {
				if (data->size != SHA256_DIGEST_LENGTH)
					PKP_SC_ERR("Pin has the wrong size 'value' (should be 32 octets for sha256)");
			}
			
		/* should we choke if it has some other key? for
		 * extensibility, we will not treat this as an
		 * error.*/
		}
	}
	
	if (errorcount > 0)
		return GETDNS_RETURN_GENERIC_ERROR;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_get_pubkey_pinset_from_list(const getdns_list *pinset_list,
				    struct mem_funcs *mf,
				    sha256_pin_t **pinset_out)
{
	getdns_return_t r;
	size_t pins, i;
	sha256_pin_t *out = NULL, *onext = NULL;
	getdns_dict * pin;
	getdns_bindata * data = NULL;
	
	if (r = getdns_list_get_length(pinset_list, &pins), r)
		return r;
	for (i = 0; i < pins; i++)
	{
		if (r = getdns_list_get_dict(pinset_list, i, &pin), r)
			goto fail;
		/* does the pin have the right digest type? */
		if (r = getdns_dict_get_bindata(pin, "digest", &data), r)
			goto fail;
		if (data->size != sha256.size ||
		    memcmp(data->data, sha256.data, sha256.size)) {
			r = GETDNS_RETURN_INVALID_PARAMETER;
			goto fail;
		}
		/* if it does, is the value the right length? */
		if (r = getdns_dict_get_bindata(pin, "value", &data), r)
			goto fail;
		if (data->size != SHA256_DIGEST_LENGTH) {
			r = GETDNS_RETURN_INVALID_PARAMETER;
			goto fail;
		}
		/* make a new pin */
		onext = GETDNS_MALLOC(*mf, sha256_pin_t);
		if (onext == NULL) {
			r = GETDNS_RETURN_MEMORY_ERROR;
			goto fail;
		}
		onext->next = out;
		memcpy(onext->pin, data->data, SHA256_DIGEST_LENGTH);
		out = onext;
	}
	
	*pinset_out = out;
	return GETDNS_RETURN_GOOD;
 fail:
	while (out) {
		onext = out->next;
		GETDNS_FREE(*mf, out);
		out = onext;
	}
	return r;
}

getdns_return_t
_getdns_get_pubkey_pinset_list(getdns_context *ctx,
			       const sha256_pin_t *pinset_in,
			       getdns_list **pinset_list)
{
	getdns_list *out = getdns_list_create_with_context(ctx);
	getdns_return_t r;
	uint8_t buf[SHA256_DIGEST_LENGTH];
	getdns_bindata value = { .size = SHA256_DIGEST_LENGTH, .data = buf };
	getdns_dict *pin = NULL;

	if (out == NULL)
		return GETDNS_RETURN_MEMORY_ERROR;
	while (pinset_in) {
		pin = getdns_dict_create_with_context(ctx);
		if (pin == NULL) {
			r = GETDNS_RETURN_MEMORY_ERROR;
			goto fail;
		}
		if (r = getdns_dict_set_bindata(pin, "digest", &sha256), r)
			goto fail;
		memcpy(buf, pinset_in->pin, sizeof(buf));
		if (r = getdns_dict_set_bindata(pin, "value", &value), r)
			goto fail;
		if (r = _getdns_list_append_this_dict(out, pin), r)
			goto fail;
		pin = NULL;
		pinset_in = pinset_in->next;
	}

	*pinset_list = out;
	return GETDNS_RETURN_GOOD;
 fail:
	getdns_dict_destroy(pin);
	getdns_list_destroy(out);
	return r;
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
_getdns_associate_upstream_with_SSL(SSL *ssl,
				    getdns_upstream *upstream)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000 || defined(HAVE_LIBRESSL)
	int uidx = _get_ssl_getdns_upstream_idx();
#else
	int uidx = _get_ssl_getdns_upstream_idx(SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl)));
#endif
	if (SSL_set_ex_data(ssl, uidx, upstream))
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
			DEBUG_STUB("%s %-35s: Pubkey %d is larger than "PRIsz" octets\n",
			           STUB_DEBUG_SETUP_TLS, __FUNC__, i, sizeof(raw));
			continue;
		}
		next = raw;
		i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &next);
		if (next - raw != len) {
			DEBUG_STUB("%s %-35s: Pubkey %d claimed it needed %d octets, really needed "PRIsz"\n",
			           STUB_DEBUG_SETUP_TLS, __FUNC__, i, len, next - raw);
			continue;
		}
		SHA256(raw, len, buf);

		/* compare it */
		for (p = pinset; p; p = p->next)
			if (0 == memcmp(buf, p->pin, sizeof(p->pin))) {
				DEBUG_STUB("%s %-35s: Pubkey %d matched pin %p ("PRIsz")\n",
					   STUB_DEBUG_SETUP_TLS, __FUNC__, i, (void*)p, sizeof(p->pin));
				return GETDNS_RETURN_GOOD;
			} else
				DEBUG_STUB("%s %-35s: Pubkey %d did not match pin %p\n",
					   STUB_DEBUG_SETUP_TLS, __FUNC__, i, (void*)p);
	}

	return ret;
}

/* pubkey-pinning.c */
