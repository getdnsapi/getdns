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
#include <string.h>
#include "context.h"
#include "util-internal.h"

#include "pubkey-pinning-internal.h"

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

/* pubkey-pinning.c */
