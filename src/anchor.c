/**
 *
 * /brief functions for DNSSEC trust anchor management
 */
/*
 * Copyright (c) 2017, NLnet Labs, Inc.
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
#include "debug.h"
#include "anchor.h"
#include <expat.h>
#include <fcntl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include "types-internal.h"
#include "context.h"

#define P7SIGNER "dnssec@iana.org"

/* The ICANN CA fetched at 24 Sep 2010.  Valid to 2028 */
static const char* _getdns_builtin_cert = 
"-----BEGIN CERTIFICATE-----\n"
"MIIDdzCCAl+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBdMQ4wDAYDVQQKEwVJQ0FO\n"
"TjEmMCQGA1UECxMdSUNBTk4gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNV\n"
"BAMTDUlDQU5OIFJvb3QgQ0ExCzAJBgNVBAYTAlVTMB4XDTA5MTIyMzA0MTkxMloX\n"
"DTI5MTIxODA0MTkxMlowXTEOMAwGA1UEChMFSUNBTk4xJjAkBgNVBAsTHUlDQU5O\n"
"IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1JQ0FOTiBSb290IENB\n"
"MQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKDb\n"
"cLhPNNqc1NB+u+oVvOnJESofYS9qub0/PXagmgr37pNublVThIzyLPGCJ8gPms9S\n"
"G1TaKNIsMI7d+5IgMy3WyPEOECGIcfqEIktdR1YWfJufXcMReZwU4v/AdKzdOdfg\n"
"ONiwc6r70duEr1IiqPbVm5T05l1e6D+HkAvHGnf1LtOPGs4CHQdpIUcy2kauAEy2\n"
"paKcOcHASvbTHK7TbbvHGPB+7faAztABLoneErruEcumetcNfPMIjXKdv1V1E3C7\n"
"MSJKy+jAqqQJqjZoQGB0necZgUMiUv7JK1IPQRM2CXJllcyJrm9WFxY0c1KjBO29\n"
"iIKK69fcglKcBuFShUECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
"Af8EBAMCAf4wHQYDVR0OBBYEFLpS6UmDJIZSL8eZzfyNa2kITcBQMA0GCSqGSIb3\n"
"DQEBCwUAA4IBAQAP8emCogqHny2UYFqywEuhLys7R9UKmYY4suzGO4nkbgfPFMfH\n"
"6M+Zj6owwxlwueZt1j/IaCayoKU3QsrYYoDRolpILh+FPwx7wseUEV8ZKpWsoDoD\n"
"2JFbLg2cfB8u/OlE4RYmcxxFSmXBg0yQ8/IoQt/bxOcEEhhiQ168H2yE5rxJMt9h\n"
"15nu5JBSewrCkYqYYmaxyOC3WrVGfHZxVI7MpIFcGdvSb2a1uyuua8l0BKgk3ujF\n"
"0/wsHNeP22qNyVO+XVBzrM8fk8BSUFuiT/6tZTYXRtEt5aKQZgXbKU5dUF3jT9qg\n"
"j/Br5BZw3X/zd325TvnswzMC1+ljLzHnQGGk\n"
"-----END CERTIFICATE-----\n";

/* get key usage out of its extension, returns 0 if no key_usage extension */
static unsigned long
_getdns_get_usage_of_ex(X509* cert)
{
	unsigned long val = 0;
	ASN1_BIT_STRING* s;

	if((s=X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL))) {
		if(s->length > 0) {
			val = s->data[0];
			if(s->length > 1)
				val |= s->data[1] << 8;
		}
		ASN1_BIT_STRING_free(s);
	}
	return val;
}

/** get valid signers from the list of signers in the signature */
static STACK_OF(X509)*
get_valid_signers(PKCS7* p7, const char* p7signer)
{
	int i;
	STACK_OF(X509)* validsigners = sk_X509_new_null();
	STACK_OF(X509)* signers = PKCS7_get0_signers(p7, NULL, 0);
	unsigned long usage = 0;
	if(!validsigners) {
		DEBUG_ANCHOR("ERROR %s(): Failed to allocated validsigners\n"
		            , __FUNC__);
		sk_X509_free(signers);
		return NULL;
	}
	if(!signers) {
		DEBUG_ANCHOR("ERROR %s(): Failed to allocated signers\n"
		            , __FUNC__);
		sk_X509_free(validsigners);
		return NULL;
	}
	for(i=0; i<sk_X509_num(signers); i++) {
		char buf[1024];
		X509_NAME* nm = X509_get_subject_name(
			sk_X509_value(signers, i));
		if(!nm) {
			DEBUG_ANCHOR("%s(): cert %d has no subject name\n"
				    , __FUNC__, i);
			continue;
		}
		if(!p7signer || strcmp(p7signer, "")==0) {
			/* there is no name to check, return all records */
			DEBUG_ANCHOR("%s(): did not check commonName of signer\n"
				    , __FUNC__);
		} else {
			if(!X509_NAME_get_text_by_NID(nm,
				NID_pkcs9_emailAddress,
				buf, (int)sizeof(buf))) {
				DEBUG_ANCHOR("%s(): removed cert with no name\n"
					    , __FUNC__);
				continue; /* no name, no use */
			}
			if(strcmp(buf, p7signer) != 0) {
				DEBUG_ANCHOR("%s(): removed cert with wrong name\n"
					    , __FUNC__);
				continue; /* wrong name, skip it */
			}
		}

		/* check that the key usage allows digital signatures
		 * (the p7s) */
		usage = _getdns_get_usage_of_ex(sk_X509_value(signers, i));
		if(!(usage & KU_DIGITAL_SIGNATURE)) {
			DEBUG_ANCHOR("%s(): removed cert with no key usage "
			             "Digital Signature allowed\n"
				    , __FUNC__);
			continue;
		}

		/* we like this cert, add it to our list of valid
		 * signers certificates */
		sk_X509_push(validsigners, sk_X509_value(signers, i));
	}
	sk_X509_free(signers);
	return validsigners;
}

static int
_getdns_verify_p7sig(BIO* data, BIO* p7s, X509_STORE *store, const char* p7signer)
{
	PKCS7* p7;
	STACK_OF(X509)* validsigners;
	int secure = 0;
#ifdef X509_V_FLAG_CHECK_SS_SIGNATURE
	X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
	if(!param) {
		DEBUG_ANCHOR("ERROR %s(): Failed to allocated param\n"
		            , __FUNC__);
		return 0;
	}
	/* do the selfcheck on the root certificate; it checks that the
	 * input is valid */
	X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CHECK_SS_SIGNATURE);
	X509_STORE_set1_param(store, param);
	X509_VERIFY_PARAM_free(param);
#endif
	(void)BIO_reset(p7s);
	(void)BIO_reset(data);

	/* convert p7s to p7 (the signature) */
	p7 = d2i_PKCS7_bio(p7s, NULL);
	if(!p7) {
		DEBUG_ANCHOR("ERROR %s(): could not parse p7s signature file\n"
		            , __FUNC__);
		return 0;
	}
	/* check what is in the Subject name of the certificates,
	 * and build a stack that contains only the right certificates */
	validsigners = get_valid_signers(p7, p7signer);
	if(!validsigners) {
		PKCS7_free(p7);
		return 0;
	}
	if(PKCS7_verify(p7, validsigners, store, data, NULL, PKCS7_NOINTERN) == 1) {
		secure = 1;
	}
#if defined(ANCHOR_DEBUG) && ANCHOR_DEBUG
	else {
		DEBUG_ANCHOR("ERROR %s(): the PKCS7 signature did not verify\n"
		            , __FUNC__);
		ERR_print_errors_cb(_getdns_ERR_print_errors_cb_f, NULL);
	}
#endif
	sk_X509_free(validsigners);
	PKCS7_free(p7);
	return secure;
}

void _getdns_context_equip_with_anchor(getdns_context *context)
{
	uint8_t xml_spc[16384], *xml_data = xml_spc;
	uint8_t p7s_spc[16384], *p7s_data = p7s_spc;
	size_t xml_len, p7s_len;

	BIO *xml = NULL, *p7s = NULL, *crt = NULL;
	X509 *x = NULL;
	X509_STORE *store = NULL;

	if (!(xml_data = _getdns_context_get_priv_file(context,
	    "root-anchors.xml", xml_spc, sizeof(xml_spc), &xml_len)))
		; /* pass */

	else if (!(p7s_data = _getdns_context_get_priv_file(context,
	    "root-anchors.p7s", p7s_spc, sizeof(p7s_spc), &p7s_len)))
		; /* pass */

	else if (!(xml = BIO_new_mem_buf(xml_data, xml_len)))
		DEBUG_ANCHOR("ERROR %s(): Failed allocating xml BIO\n"
		            , __FUNC__);

	else if (!(p7s = BIO_new_mem_buf(p7s_data, p7s_len)))
		DEBUG_ANCHOR("ERROR %s(): Failed allocating p7s BIO\n"
		            , __FUNC__);
	
	else if (!(crt = BIO_new_mem_buf(_getdns_builtin_cert, -1)))
		DEBUG_ANCHOR("ERROR %s(): Failed allocating crt BIO\n"
		            , __FUNC__);

	else if (!(x = PEM_read_bio_X509(crt, NULL, 0, NULL)))
		DEBUG_ANCHOR("ERROR %s(): Parsing builtin certificate\n"
		            , __FUNC__);

	else if (!(store = X509_STORE_new()))
		DEBUG_ANCHOR("ERROR %s(): Failed allocating store\n"
		            , __FUNC__);

	else if (!X509_STORE_add_cert(store, x))
		DEBUG_ANCHOR("ERROR %s(): Adding certificate to store\n"
		            , __FUNC__);

	else if (_getdns_verify_p7sig(xml, p7s, store, "dnssec@iana.org")) {
		DEBUG_ANCHOR("Verifying trust-anchors SUCCEEDED, Yay!\n");
	} else {
		DEBUG_ANCHOR("Verifying trust-anchors failed!\n");
	}
	if (store)	X509_STORE_free(store);
	if (x)		X509_free(x);
	if (crt)	BIO_free(crt);
	if (xml)	BIO_free(xml);
	if (p7s)	BIO_free(p7s);
	if (xml_data && xml_data != xml_spc)
		GETDNS_FREE(context->mf, xml_data);
	if (p7s_data && p7s_data != p7s_spc)
		GETDNS_FREE(context->mf, p7s_data);
}

/* anchor.c */
