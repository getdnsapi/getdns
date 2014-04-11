/**
 *
 * /brief function for DANE
 *
 * The getdns_dane_verify function is used to match and validate TLSAs with a
 * certificate.
 */

/*
 * Copyright (c) 2014, NLnet Labs, Verisign, Inc.
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

#include "getdns/getdns.h"
#include "getdns/getdns_extra.h"
#include "config.h"
#include "rr-dict.h"

#ifdef HAVE_LDNS_DANE_VERIFY
#include <ldns/dane.h>

int
getdns_dane_verify(getdns_list *tlsa_rr_dicts, X509 *cert,
    STACK_OF(X509) *extra_certs, X509_STORE *pkix_validation_store)
{
	getdns_return_t r;
	ldns_rr_list *tlsas;

	if ((r = priv_getdns_rr_list_from_list(tlsa_rr_dicts, &tlsas)))
		return r;

	switch (ldns_dane_verify(tlsas, cert,
	                         extra_certs, pkix_validation_store)) {
	case LDNS_STATUS_OK:
		return GETDNS_RETURN_GOOD;
	case LDNS_STATUS_DANE_PKIX_DID_NOT_VALIDATE:
		return GETDNS_DANE_PKIX_DID_NOT_VALIDATE;
	case LDNS_STATUS_DANE_TLSA_DID_NOT_MATCH:
		return GETDNS_DANE_TLSA_DID_NOT_MATCH;
	default:
		break;
	}
	return GETDNS_RETURN_GENERIC_ERROR;
}

#else	/* HAVE_LDNS_DANE_VERIFY */

getdns_dane_verify(getdns_list *tlsa_rr_dicts, X509 *cert,
    STACK_OF(X509) *extra_certs, X509_STORE *pkix_validation_store)
{
	(void) tlsa_rr_dicts;
	(void) cert;
	(void) extra_certs;
	(void) pkix_validation_store;
	return GETDNS_RETURN_NOT_IMPLEMENTED;
}

#endif	/* HAVE_LDNS_DANE_VERIFY */

/* dane.c */
