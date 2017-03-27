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

#define P7SIGNER "dnssec@iana.org"

static const char*
get_builtin_cert(void)
{
	return
/* The ICANN CA fetched at 24 Sep 2010.  Valid to 2028 */
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
}

/* get key usage out of its extension, returns 0 if no key_usage extension */
static unsigned long
get_usage_of_ex(X509* cert)
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
	const int verb = 5;
	int i;
	STACK_OF(X509)* validsigners = sk_X509_new_null();
	STACK_OF(X509)* signers = PKCS7_get0_signers(p7, NULL, 0);
	unsigned long usage = 0;
	if(!validsigners) {
		if(verb) printf("out of memory\n");
		sk_X509_free(signers);
		return NULL;
	}
	if(!signers) {
		if(verb) printf("no signers in pkcs7 signature\n");
		sk_X509_free(validsigners);
		return NULL;
	}
	for(i=0; i<sk_X509_num(signers); i++) {
		X509_NAME* nm = X509_get_subject_name(
			sk_X509_value(signers, i));
		char buf[1024];
		if(!nm) {
			if(verb) printf("signer %d: cert has no subject name\n", i);
			continue;
		}
		if(verb && nm) {
			char* nmline = X509_NAME_oneline(nm, buf,
				(int)sizeof(buf));
			printf("signer %d: Subject: %s\n", i,
				nmline?nmline:"no subject");
			if(verb >= 3 && X509_NAME_get_text_by_NID(nm,
				NID_commonName, buf, (int)sizeof(buf)))
				printf("commonName: %s\n", buf);
			if(verb >= 3 && X509_NAME_get_text_by_NID(nm,
				NID_pkcs9_emailAddress, buf, (int)sizeof(buf)))
				printf("emailAddress: %s\n", buf);
		}
		if(verb) {
			int ku_loc = X509_get_ext_by_NID(
				sk_X509_value(signers, i), NID_key_usage, -1);
			if(verb >= 3 && ku_loc >= 0) {
				X509_EXTENSION *ex = X509_get_ext(
					sk_X509_value(signers, i), ku_loc);
				if(ex) {
					printf("keyUsage: ");
					X509V3_EXT_print_fp(stdout, ex, 0, 0);
					printf("\n");
				}
			}
		}
		if(!p7signer || strcmp(p7signer, "")==0) {
			/* there is no name to check, return all records */
			if(verb) printf("did not check commonName of signer\n");
		} else {
			if(!X509_NAME_get_text_by_NID(nm,
				NID_pkcs9_emailAddress,
				buf, (int)sizeof(buf))) {
				if(verb) printf("removed cert with no name\n");
				continue; /* no name, no use */
			}
			if(strcmp(buf, p7signer) != 0) {
				if(verb) printf("removed cert with wrong name\n");
				continue; /* wrong name, skip it */
			}
		}

		/* check that the key usage allows digital signatures
		 * (the p7s) */
		usage = get_usage_of_ex(sk_X509_value(signers, i));
		if(!(usage & KU_DIGITAL_SIGNATURE)) {
			if(verb) printf("removed cert with no key usage Digital Signature allowed\n");
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
verify_p7sig(BIO* data, BIO* p7s, X509_STORE *store, const char* p7signer)
{
	const int verb = 5;
	PKCS7* p7;
	STACK_OF(X509)* validsigners;
	int secure = 0;
#ifdef X509_V_FLAG_CHECK_SS_SIGNATURE
	X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
	if(!param) {
		if(verb) printf("out of memory\n");
		X509_STORE_free(store);
		return 0;
	}
	/* do the selfcheck on the root certificate; it checks that the
	 * input is valid */
	X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CHECK_SS_SIGNATURE);
	if(store) X509_STORE_set1_param(store, param);
#endif
	if(!store) {
		if(verb) printf("out of memory\n");
#ifdef X509_V_FLAG_CHECK_SS_SIGNATURE
		X509_VERIFY_PARAM_free(param);
#endif
		return 0;
	}
#ifdef X509_V_FLAG_CHECK_SS_SIGNATURE
	X509_VERIFY_PARAM_free(param);
#endif

	(void)BIO_reset(p7s);
	(void)BIO_reset(data);

	/* convert p7s to p7 (the signature) */
	p7 = d2i_PKCS7_bio(p7s, NULL);
	if(!p7) {
		if(verb) printf("could not parse p7s signature file\n");
		X509_STORE_free(store);
		return 0;
	}
	if(verb >= 2) printf("parsed the PKCS7 signature\n");

	/* check what is in the Subject name of the certificates,
	 * and build a stack that contains only the right certificates */
	validsigners = get_valid_signers(p7, p7signer);
	if(!validsigners) {
		PKCS7_free(p7);
		return 0;
	}
	BIO *out = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
	BIO_printf(out, "Hello World\n");
	if(PKCS7_verify(p7, validsigners, store, data, out, PKCS7_NOINTERN) == 1) {
		secure = 1;
		if(verb) printf("the PKCS7 signature verified\n");
	} else {
		if(verb) printf("the PKCS7 signature did not verify\n");
		if(verb) {
			ERR_print_errors_fp(stdout);
		}
	}
	BIO_free(out);

	sk_X509_free(validsigners);
	PKCS7_free(p7);
	return secure;
}

void _getdns_context_equip_with_anchor(getdns_context *context)
{
	char fn[1024];
	int xml_fd, p7s_fd;
	int n;
	BIO *xml, *p7s, *crt;
	X509 *x;
	X509_STORE *store;
	char *crt_str;

	DEBUG_ANCHOR("entering %s\n", __FUNC__);
	
	n = snprintf( fn, sizeof(fn)
	            , "%s/.getdns/root-anchors.xml", getenv("HOME"));

	if (n < 0 || n >= (int)sizeof(fn))
		return;

	if ((xml_fd = open(fn, O_RDONLY)) < 0)
		return;

	(void) snprintf( fn, sizeof(fn)
	               , "%s/.getdns/root-anchors.p7s", getenv("HOME"));

	if ((p7s_fd = open(fn, O_RDONLY)) < 0) {
		close(xml_fd);
		return;
	}
	if (!(xml = BIO_new_fd(xml_fd, 1))) {
		close(xml_fd);
		close(p7s_fd);
		return;
	}
	if (!(p7s = BIO_new_fd(p7s_fd, 1))) {
		BIO_free(xml);
		close(p7s_fd);
		return;
	}
	if (!(crt_str = strdup(get_builtin_cert())))
		goto error_free_xml;
	if (!(crt = BIO_new_mem_buf(crt_str, (int)strlen(crt_str))))
		goto error_free_str;
       	if (!(store = X509_STORE_new()))
		goto error_free_crt;
	if (!(x = PEM_read_bio_X509(crt, NULL, 0, NULL)))
		goto error_free_store;
	if (!X509_STORE_add_cert(store, x))
		goto error_free_store;
	if (verify_p7sig(xml, p7s, store, "dnssec@iana.org")) {
		DEBUG_ANCHOR("Verifying trust-anchors SUCCEEDED, Yay!\n");
		;
	} else {
		DEBUG_ANCHOR("Verifying trust-anchors failed!\n");
		;
	}
error_free_store:
	X509_STORE_free(store);
error_free_crt:
	BIO_free(crt);
error_free_str:
	free(crt_str);
error_free_xml:
	BIO_free(xml);
	BIO_free(p7s);
}

/* anchor.c */
