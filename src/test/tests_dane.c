/**
 * \file
 * unit tests for getdns_dict helper routines, these should be used to
 * perform regression tests, output must be unchanged from canonical output
 * stored with the sources
 */

/*
 * Copyright (c) 2014, NLNet Labs, Verisign, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef getdns_get_errorstr_by_id
const char *getdns_get_errorstr_by_id(uint16_t err);
#endif

#ifdef HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>

#define GETDNS_DANE_TLSA_DID_NOT_MATCH 3000
#define GETDNS_DANE_TLSA_DID_NOT_MATCH_TEXT "None of the given TLSAs matched"
#define GETDNS_DANE_PKIX_DID_NOT_VALIDATE 3001
#define GETDNS_DANE_PKIX_DID_NOT_VALIDATE_TEXT \
	"A TLSA matched but PKIX validation failed."
#define GETDNS_DANE_NON_CA_CERTIFICATE 3002
#define GETDNS_DANE_NON_CA_CERTIFICATE_TEXT \
	"A non CA certificate is matched"

#define GETDNS_DANE_USAGE_PKIX_TA 0
#define GETDNS_DANE_USAGE_PKIX_EE 1
#define GETDNS_DANE_USAGE_DANE_TA 2
#define GETDNS_DANE_USAGE_DANE_EE 3

#define GETDNS_DANE_SELECTOR_CERT 0
#define GETDNS_DANE_SELECTOR_SPKI 1

#define GETDNS_DANE_MATCHING_TYPE_FULL     0
#define GETDNS_DANE_MATCHING_TYPE_SHA2_256 1
#define GETDNS_DANE_MATCHING_TYPE_SHA2_512 2

/* Ordinary PKIX validation of cert (with extra_certs to help)
 * against the CA's in store
 */
static int
getdns_dane_pkix_validate(
    X509* cert, STACK_OF(X509)* extra_certs, X509_STORE* store)
{
	X509_STORE_CTX* vrfy_ctx;
	int r;

	if (! store)
		return GETDNS_DANE_PKIX_DID_NOT_VALIDATE;

	vrfy_ctx = X509_STORE_CTX_new();
	if (! vrfy_ctx)
		return GETDNS_RETURN_MEMORY_ERROR;

	else if (X509_STORE_CTX_init(vrfy_ctx, store,
				cert, extra_certs) != 1)
		r = GETDNS_RETURN_GENERIC_ERROR;

	else if (X509_verify_cert(vrfy_ctx) == 1)
		r = GETDNS_RETURN_GOOD;
	else
		r = GETDNS_DANE_PKIX_DID_NOT_VALIDATE;

	X509_STORE_CTX_free(vrfy_ctx);
	return r;
}


/* Ordinary PKIX validation of cert (with extra_certs to help)
 * against the CA's in store, but also return the validation chain.
 */
static int
getdns_dane_pkix_validate_and_get_chain(STACK_OF(X509)** chain, X509* cert,
    STACK_OF(X509)* extra_certs, X509_STORE* store)
{
	int r;
	X509_STORE* empty_store = NULL;
	X509_STORE_CTX* vrfy_ctx;

	if (! store)
		store = empty_store = X509_STORE_new();

	r = GETDNS_RETURN_GENERIC_ERROR;
	vrfy_ctx = X509_STORE_CTX_new();
	if (! vrfy_ctx)
		goto exit_free_empty_store;

	else if (X509_STORE_CTX_init(vrfy_ctx, store,
					cert, extra_certs) != 1)
		goto exit_free_vrfy_ctx;

	else if (X509_verify_cert(vrfy_ctx) == 1)
		r = GETDNS_RETURN_GOOD;
	else
		r = GETDNS_DANE_PKIX_DID_NOT_VALIDATE;

	*chain = X509_STORE_CTX_get1_chain(vrfy_ctx);
	if (! *chain)
		r = GETDNS_RETURN_GENERIC_ERROR;

exit_free_vrfy_ctx:
	X509_STORE_CTX_free(vrfy_ctx);

exit_free_empty_store:
	if (empty_store)
		X509_STORE_free(empty_store);
	return r;
}


/* Return the validation chain that can be build out of cert, with extra_certs.
 */
static int
getdns_dane_pkix_get_chain(STACK_OF(X509)** chain,
    X509* cert, STACK_OF(X509)* extra_certs)
{
	int r;
	X509_STORE* empty_store = NULL;
	X509_STORE_CTX* vrfy_ctx;

	empty_store = X509_STORE_new();
	r = GETDNS_RETURN_GENERIC_ERROR;
	vrfy_ctx = X509_STORE_CTX_new();
	if (! vrfy_ctx)
		goto exit_free_empty_store;

	else if (X509_STORE_CTX_init(vrfy_ctx, empty_store,
					cert, extra_certs) != 1)
		goto exit_free_vrfy_ctx;

	(void) X509_verify_cert(vrfy_ctx);
	*chain = X509_STORE_CTX_get1_chain(vrfy_ctx);
	if (! *chain)
		r = GETDNS_RETURN_GENERIC_ERROR;
	else
		r = GETDNS_RETURN_GOOD;

exit_free_vrfy_ctx:
	X509_STORE_CTX_free(vrfy_ctx);

exit_free_empty_store:
	X509_STORE_free(empty_store);
	return r;
}

/* Return whether cert/selector/matching_type matches data.
 */
static int
getdns_dane_match_cert_with_data(X509* cert,
    uint32_t selector, uint32_t matching_type, getdns_bindata *data)
{
	int r = GETDNS_RETURN_GOOD;

	unsigned char *buf = NULL;
	size_t len;

	X509_PUBKEY* xpubkey;
	EVP_PKEY* epubkey;

	unsigned char hash[SHA512_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	switch (selector) {
	case GETDNS_DANE_SELECTOR_CERT:

		len = (size_t)i2d_X509(cert, &buf);
		break;

	case GETDNS_DANE_SELECTOR_SPKI:

		xpubkey = X509_get_X509_PUBKEY(cert);
		if (! xpubkey)
			return GETDNS_RETURN_GENERIC_ERROR;

		epubkey = X509_PUBKEY_get(xpubkey);
		if (! epubkey)
			return GETDNS_RETURN_GENERIC_ERROR;

		len = (size_t)i2d_PUBKEY(epubkey, &buf);
		break;
	
	default:
		return GETDNS_RETURN_GENERIC_ERROR;
	}

	switch(matching_type) {
	case GETDNS_DANE_MATCHING_TYPE_FULL:

		if (data->size != len || memcmp(data->data, buf, len))
			r = GETDNS_DANE_TLSA_DID_NOT_MATCH;
		break;
	
	case GETDNS_DANE_MATCHING_TYPE_SHA2_256:

		if (data->size != SHA256_DIGEST_LENGTH)
			r = GETDNS_DANE_TLSA_DID_NOT_MATCH;
		else {
			SHA256_Init(&sha256);
			SHA256_Update(&sha256, buf, len);
			SHA256_Final(hash, &sha256);
			if (memcmp(data->data, hash, SHA256_DIGEST_LENGTH))
				r = GETDNS_DANE_TLSA_DID_NOT_MATCH;
		}
		break;

	case GETDNS_DANE_MATCHING_TYPE_SHA2_512:

		if (data->size != SHA512_DIGEST_LENGTH)
			r = GETDNS_DANE_TLSA_DID_NOT_MATCH;
		else {
			SHA512_Init(&sha512);
			SHA512_Update(&sha512, buf, len);
			SHA512_Final(hash, &sha512);
			if (memcmp(data->data, hash, SHA512_DIGEST_LENGTH))
				r = GETDNS_DANE_TLSA_DID_NOT_MATCH;
		}
		break;
	
	default:
		r = GETDNS_RETURN_GENERIC_ERROR;
	}
	free(buf);
	return r;
}

/* Return whether any certificate from the chain with selector/matching_type
 * matches data.
 * ca should be 1 if the certificate has to be a CA certificate too.
 */
static int
getdns_dane_match_any_cert_with_data(STACK_OF(X509)* chain,
    uint32_t selector, uint32_t matching_type, getdns_bindata* data, int ca)
{
	int r = GETDNS_DANE_TLSA_DID_NOT_MATCH;
	size_t n, i;
	X509* cert;

	n = (size_t)sk_X509_num(chain);
	for (i = 0; i < n; i++) {
		cert = sk_X509_pop(chain);
		if (! cert) {
			r = GETDNS_RETURN_GENERIC_ERROR;
			break;
		}
		r = getdns_dane_match_cert_with_data(
		    cert, selector, matching_type, data);
		if (ca && r == GETDNS_RETURN_GOOD && ! X509_check_ca(cert))
			r = GETDNS_DANE_NON_CA_CERTIFICATE;
		X509_free(cert);
		if (r != GETDNS_DANE_TLSA_DID_NOT_MATCH)
			break;
		/* when r == GETDNS_DANE_TLSA_DID_NOT_MATCH,
		 * try to match the next certificate
		 */
	}
	return r;
}

int /* actually extended getdns_return_t */
getdns_dane_verify(getdns_list *tlsas, X509 *cert,
    STACK_OF(X509) *extra_certs, X509_STORE *pkix_validation_store )
{
	getdns_return_t r = GETDNS_RETURN_GOOD, prev_r = GETDNS_RETURN_GOOD;
	size_t tlsas_len, i, n_tlsas;
	getdns_dict *tlsa_rr;
	uint32_t rr_type;
	getdns_dict *rdata;
	uint32_t usage, selector, matching_type;
	getdns_bindata *data; /* Certificate association data */
	STACK_OF(X509) *pkix_validation_chain;

	if ((r = getdns_list_get_length(tlsas, &tlsas_len)))
		return r;

	for (n_tlsas = 0, i = 0; i < tlsas_len; i++) {

		prev_r = r;

		if ((r = getdns_list_get_dict(tlsas, i, &tlsa_rr)))
			break;

		if ((r = getdns_dict_get_int(tlsa_rr, "type", &rr_type)))
			break;

		if (rr_type != GETDNS_RRTYPE_TLSA
		    || (r = getdns_dict_get_dict(tlsa_rr, "rdata", &rdata))
		    || (r = getdns_dict_get_int(rdata,
		        "certificate_usage" , &usage))
		    || (r = getdns_dict_get_int(rdata,
		        "selector", &selector))
		    || (r = getdns_dict_get_int(rdata,
		        "matching_type", &matching_type))
		    || (r = getdns_dict_get_bindata(rdata,
		        "certificate_association_data", &data))
		    || usage > 3 || selector > 1 || matching_type > 2) {

			r = prev_r;
			continue;
		} else
			n_tlsas++;

		pkix_validation_chain = NULL;
		switch (usage) {
		case GETDNS_DANE_USAGE_PKIX_TA:
			r = getdns_dane_pkix_validate_and_get_chain(
			    &pkix_validation_chain, 
			    cert, extra_certs,
			    pkix_validation_store);

			if (! pkix_validation_chain)
				break;
			if (r == GETDNS_DANE_PKIX_DID_NOT_VALIDATE) {
				/*
				 * NO PKIX validation. We still try to match
				 * *any* certificate from the chain, so we
				 * return TLSA errors over PKIX errors.
				 *
				 * i.e. When the TLSA matches no certificate,
				 *  we return * TLSA_DID_NOT_MATCH and not
				 * PKIX_DID_NOT_VALIDATE
				 */
				r = getdns_dane_match_any_cert_with_data(
				    pkix_validation_chain,
				    selector, matching_type, data, 1);

				if (r == GETDNS_RETURN_GOOD) {
					/* A TLSA record did match a cert from
					 * the chain, thus the error is failed
					 * PKIX validation.
					 */
					r = GETDNS_DANE_PKIX_DID_NOT_VALIDATE;
				}

			} else if (r == GETDNS_RETURN_GOOD) { 
				/* PKIX validated, does the TLSA match too? */

				r = getdns_dane_match_any_cert_with_data(
				    pkix_validation_chain,
				    selector, matching_type, data, 1);
			}
			sk_X509_pop_free(pkix_validation_chain, X509_free);
			break;

		case GETDNS_DANE_USAGE_PKIX_EE:
			r = getdns_dane_match_cert_with_data(
			    cert, selector, matching_type, data);

			r = r ? r : getdns_dane_pkix_validate(
				    cert, extra_certs, pkix_validation_store);
			break;

		case GETDNS_DANE_USAGE_DANE_TA:
			r = getdns_dane_pkix_get_chain(
			    &pkix_validation_chain, cert, extra_certs);

			r = r ? r : getdns_dane_match_any_cert_with_data(
			    pkix_validation_chain,
			    selector, matching_type, data, 0);

			 if (pkix_validation_chain)
				sk_X509_pop_free(
				    pkix_validation_chain, X509_free);
			break;

		case GETDNS_DANE_USAGE_DANE_EE:
			r = getdns_dane_match_cert_with_data(
			    cert, selector, matching_type, data);
			break;
		default:
			r = GETDNS_RETURN_GENERIC_ERROR;
			break;
		}

		if (r != GETDNS_DANE_TLSA_DID_NOT_MATCH &&
		    r != GETDNS_DANE_PKIX_DID_NOT_VALIDATE) {

			/* which would be GETDNS_RETURN_GOOD (match)
			 * or some fatal error preventing use from
			 * trying the next TLSA record.
			 */
			break;
		}
		r = (r < prev_r ? prev_r : r); /* prefer PKIX_DID_NOT_VALIDATE
		                                * over   TLSA_DID_NOT_MATCH
		                                */
	}
	if (n_tlsas == 0)
		return getdns_dane_pkix_validate(
		    cert, extra_certs, pkix_validation_store);

	return r;
}

void
print_usage(const char *progname, FILE *out, int exit_code)
{
	fprintf(out, "usage: %s [OPTIONS] <hostname> [ <port> ]\n", progname);
	fprintf(out, "\n\t<port> defaults to 443\n");
	fprintf(out, "\nOPTIONS:\n");
	fprintf(out, "\t-h\t\tshow this text\n");
	fprintf(out, "\t-f <CAfile>\tuse CAfile for PKIX validation\n");
	fprintf(out, "\t-p <CApath>\tuse certificates in the <CApath> "
	    "for PKIX validation\n");
	exit(exit_code);
}

int
main(int argc, char * const *argv)
{
	getdns_return_t r;

	const char *progname;
	int         opt;
	const char *CAfile = NULL;
	const char *CApath = NULL;

	const char *hostname;
	int         port = 443;
	char        danename[1024];

	getdns_context *context;
	getdns_dict    *response;
	getdns_dict    *extensions;
	getdns_list    *replies_tree;
	uint32_t        status;
	getdns_dict    *reply;
	getdns_list    *tlsas;
	size_t         ntlsas;
	getdns_dict    *response2;
	getdns_list    *addresses;
	size_t         naddresses, i;
	SSL_CTX        *ctx;
	X509_STORE     *certificate_authorities = NULL;
	getdns_dict    *address;

	getdns_bindata *address_type;
	getdns_bindata *address_data;

	struct sockaddr_storage sas;
	struct sockaddr_in     *sa4 = (struct sockaddr_in *)&sas;
	struct sockaddr_in6    *sa6 = (struct sockaddr_in6 *)&sas;
	size_t                  sa_len;

	char           *address_str;
	int             sock;
	SSL            *ssl;
	int             ssl_status;

	X509           *cert;
	STACK_OF(X509) *extra_certs;


	/* Number of successfully validated addresses */
	int             nsuccess = 0;

	/*
	 * Process command line options to deterine the localtion of the
	 * certificate authorities.
	 */
	if ((progname = strrchr(argv[0], '/')))
		progname++;
	else
		progname = argv[0];

	while ((opt = getopt(argc, argv, "f:hp:")) != -1) {
		switch(opt) {
		case 'h': print_usage(progname, stdout, EXIT_SUCCESS);
		case 'f': CAfile = optarg;
			  break;
		case 'p': CApath = optarg;
			  break;
		}
	}
	argc -= optind;
	argv += optind;

	/*
	 * Get hostname and optional port from commandline arguments.
	 */
	if (argc == 2)
		port = atoi(argv[1]);

	else if (argc != 1)
		print_usage(progname, stderr, EXIT_FAILURE);

	hostname = argv[0];

	/*
	 * Setup getdns stub resolution
	 */
       	if ((r = getdns_context_create(&context, 1))) {
		fprintf(stderr, "Error creating context: %s\n",
		    getdns_get_errorstr_by_id(r));
		return EXIT_FAILURE;
	}

	/*
	if ((r = getdns_context_set_resolution_type(
	    context, GETDNS_RESOLUTION_STUB))) {
		fprintf(stderr, "Error setting stub resolution: %s\n",
		    getdns_get_errorstr_by_id(r));

		goto done_destroy_context;
	}
	*/

	if (! (extensions = getdns_dict_create())) {

		r = GETDNS_RETURN_MEMORY_ERROR;
		fprintf(stderr, "Error creating extensions dict: %s\n",
		    getdns_get_errorstr_by_id(r));
		goto done_destroy_context;
	}

	/*
	 * Lookup TLSA's (but only when they are secure (i.e. DNSSEC signed))
	 */
	if ((r = getdns_dict_set_int(
	    extensions, "dnssec_return_only_secure", GETDNS_EXTENSION_TRUE))) {

		r = GETDNS_RETURN_MEMORY_ERROR;
		fprintf(stderr, "Error setting dnssec_return_only_secure "
		    "extension: %s\n", getdns_get_errorstr_by_id(r));
		goto done_destroy_extensions;
	}

	/* construct the dane name */
	(void) snprintf(danename, 1024, "_%d._tcp.%s", port, hostname);

	/* actual lookup */
	if ((r = getdns_general_sync(context,
	    danename, GETDNS_RRTYPE_TLSA, extensions, &response))) {

		fprintf(stderr, "Error looking up TLSA records: %s\n",
		    getdns_get_errorstr_by_id(r));
		goto done_destroy_extensions;
	}

	/* Did we get anything?  Securely? */
	if ((r = getdns_dict_get_int(response, "status", &status))) {

		fprintf(stderr, "Error getting status from response dict: "
		    "%s\n", getdns_get_errorstr_by_id(r));
		goto done_destroy_response;
	}

	if (status == GETDNS_RESPSTATUS_NO_SECURE_ANSWERS) {
		printf("No secure TLSA RR's for %s were found.\n", danename);
		printf("PKIX validation without dane will be performed.\n");
		tlsas = NULL;
		ntlsas = 0;

	} else {
		/* descend into response dict to get to the tlsas */
		if ((r = getdns_dict_get_list(
		    response, "replies_tree", &replies_tree))) {

			fprintf(stderr, "Error getting replies_tree from res"
			    "ponse dict: %s\n", getdns_get_errorstr_by_id(r));
			goto done_destroy_response;
		}
		
		if ((r = getdns_list_get_dict(replies_tree, 0, &reply))) {

			fprintf(stderr, "Error getting first reply from rep"
			    "lies_tree: %s\n", getdns_get_errorstr_by_id(r));
			goto done_destroy_response;
		}

		if ((r = getdns_dict_get_list(reply, "answer", &tlsas))) {

			fprintf(stderr, "Error getting tlsas from reply: %s\n",
			    getdns_get_errorstr_by_id(r));
			goto done_destroy_response;
		}

		if ((r = getdns_list_get_length(tlsas, &ntlsas))) {

			fprintf(stderr, "Error getting the lenth of the tlsas "
			    "list: %s\n", getdns_get_errorstr_by_id(r));
			goto done_destroy_response;
		}

		if (ntlsas == 0) {
			printf("No TLSA RR's for %s were found.\n", danename);
			printf("PKIX validation "
			    "without dane will be performed.\n");
		}
	}
	/*
	 * Lookup addresses for the hostname (don't have to be secure).
	 */
	if ((r = getdns_address_sync(context, hostname, NULL, &response2))) {

		fprintf(stderr, "Error looking up address records for "
		    "%s: %s\n", hostname, getdns_get_errorstr_by_id(r));
		goto done_destroy_response;
	}

	/* get the addresses from the response dict */
	if ((r = getdns_dict_get_list(response2, "just_address_answers",
	    &addresses))) {

		fprintf(stderr, "Error getting addresses from the address look"
		    "up response dict: %s\n", getdns_get_errorstr_by_id(r));
		goto done_destroy_response2;
	}

	/* exit when there are none  */
	if ((r = getdns_list_get_length(addresses, &naddresses))) {

		fprintf(stderr, "Error getting the lenth of the addresses"
		    "list: %s\n", getdns_get_errorstr_by_id(r));
		goto done_destroy_response2;
	}
	if (naddresses <= 0) {
		printf("%s did not have any addresses to connect to\n",
		    hostname);
		goto done_destroy_response2;
	}

	/*
	 * Initialize OpenSSL
	 */
	SSL_load_error_strings();
	SSL_library_init();

	/*
	 * Setup certificate authorities store
	 */
	if (CAfile || CApath) {
		certificate_authorities = X509_STORE_new();
		if (! certificate_authorities) {
			fprintf(stderr, "could not create store for the "
			    "certificate authorities\n");
			ERR_print_errors_fp(stderr);
			r = EXIT_FAILURE;
			goto done_destroy_response2;
		}
		if (X509_STORE_load_locations(certificate_authorities,
		    CAfile, CApath) != 1) {
			fprintf(stderr, "Error loading certificate "
			    "authorities from %s", CAfile ? CAfile : CApath);
			if (CAfile && CApath)
				fprintf(stderr, " and/or %s", CApath);
			fprintf(stderr, "\n");
			ERR_print_errors_fp(stderr);
		}
	}

	/*
	 * Setup OpenSSL context
	 */
	ctx = SSL_CTX_new(SSLv23_client_method());
	if (! ctx) {
		fprintf(stderr, "could not create an SSL context\n");
		ERR_print_errors_fp(stderr);
		r = EXIT_FAILURE;
		goto done_destroy_certificate_authorities;
	}

	/*
	 * For each address SSL connect and get and verify the certificate
	 */
	for (i = 0; i < naddresses && r == GETDNS_RETURN_GOOD; i++) {

		if ((r = getdns_list_get_dict(addresses, i, &address))) {

			fprintf(stderr, "Error getting address from the addres"
			    "ses list: %s\n", getdns_get_errorstr_by_id(r));
			break;
		}

		/*
		 * Create a sockaddr_in from <address> <port>
		 * (Quiet involved yes)
		 */
		if ((r = getdns_dict_get_bindata(
		    address, "address_type", &address_type))) {

			fprintf(stderr, "Error getting address_type from "
			    "address: %s\n", getdns_get_errorstr_by_id(r));
			break;
		}

		if ((r = getdns_dict_get_bindata(
		    address, "address_data", &address_data))) {

			fprintf(stderr, "Error getting address_data from "
			    "address: %s\n", getdns_get_errorstr_by_id(r));
			break;
		}

		if (0 ==
		    strncmp((const char *)address_type->data, "IPv4", 4)) {

			sas.ss_family = AF_INET;
			sa4->sin_port = htons(port);
			memcpy(&(sa4->sin_addr),address_data->data,
			    address_data->size < 4 ? address_data->size : 4);
			sa_len = sizeof(struct sockaddr_in);

		} else if (0 ==
		    strncmp((const char *)address_type->data, "IPv6", 4)) {

			sas.ss_family = AF_INET6;
			sa6->sin6_port = htons(port);
			memcpy(&(sa6->sin6_addr), address_data->data,
			    address_data->size < 16 ? address_data->size : 16);
			sa_len = sizeof(struct sockaddr_in6);

		} else  {
			fprintf(stderr, "Unknown address type, must be either "
			    "\"IPv4\" or \"IPv6\"\n");
			r = EXIT_FAILURE;
			break;
		}

		/*
		 * Open and tcp-connect a socket with this sockaddr_in
		 */
		sock = socket(sas.ss_family, SOCK_STREAM, IPPROTO_TCP);
		if (sock == -1) {

			perror("Error creating socket");
			r = EXIT_FAILURE;
			break;
		}

		/* display connection details */
		address_str = getdns_display_ip_address(address_data);
		printf("Connecting to %s%s%s:%d... ",
		    (sas.ss_family == AF_INET6 ? "[" : ""), address_str,
		    (sas.ss_family == AF_INET6 ? "]" : ""), port);
		free(address_str);

		/* and connect */
		if (connect(sock, (struct sockaddr *)&sas, sa_len) == -1) {
			printf("failed (%s)\n", strerror(errno));
			close(sock);
			continue;
		}

		/*
		 * Create ssl
		 */
		ssl = SSL_new(ctx);
		if (! ssl) {
			printf("failed setting up ssl (creating)\n");
			ERR_print_errors_fp(stderr);
			close(sock);
			continue;
		}

		/*
		 * Associate ssl with the hostname
		 */
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
		(void) SSL_set_tlsext_host_name(ssl, hostname);
#endif

		/*
		 * Associate ssl with the connected socket
		 */
		SSL_set_connect_state(ssl);
		(void) SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		if (! SSL_set_fd(ssl, sock)) {
			printf("failed setting up ssl (associating socket)\n");
			ERR_print_errors_fp(stderr);
			SSL_free(ssl);
			close(sock);
			continue;
		}

		/*
		 * Shake hands (Quiet involved yes)
		 */
		for (;;) {
			ERR_clear_error();
			if ((ssl_status = SSL_do_handshake(ssl)) == 1) {
				break;
			}
			ssl_status = SSL_get_error(ssl, ssl_status);
			if (ssl_status != SSL_ERROR_WANT_READ &&
			    ssl_status != SSL_ERROR_WANT_WRITE) {
				r = GETDNS_RETURN_GENERIC_ERROR;
				break;
			}
		}
		if (r == GETDNS_RETURN_GENERIC_ERROR) {
			r = GETDNS_RETURN_GOOD;
			printf("failed setting up ssl (handshaking)\n");
			ERR_print_errors_fp(stderr);
			SSL_free(ssl);
			close(sock);
			continue;
		}

		/*
		 * Get the certificates from the chain.
		 */
		cert = SSL_get_peer_certificate(ssl);
		extra_certs = SSL_get_peer_cert_chain(ssl);

		/*
		 * Dane validate the certificate
		 */
		int s;
		switch ((s = getdns_dane_verify(tlsas, cert, extra_certs,
		                           certificate_authorities))) {
		case GETDNS_RETURN_GOOD:

			/*****************************************************
			 *****************************************************
			 **** 
			 **** At this point we have a properly DANE 
			 **** authenticated ssl connection and can start
			 **** interacting.
			 **** 
			 **** Our example application simply prints the
			 **** status (of successfull validation) and
			 **** continues checking the next address (if any).
			 **** 
			 *****************************************************
			 *****************************************************/

			printf("dane-validated successfully.\n");
			nsuccess++;
			break;

		case GETDNS_DANE_PKIX_DID_NOT_VALIDATE:
			if (ntlsas) printf("A TLSA matched, but ");
			printf("PKIX validation failed\n");
			break;

		case GETDNS_DANE_TLSA_DID_NOT_MATCH:
			printf("No matching TLSA found\n");
			break;
		default:
			printf("An error occurred when verifying TLSA's (%d)\n", s);
			break;
		}
		while (SSL_shutdown(ssl) == 0);
		SSL_free(ssl);

	} /* for (i = 0; i < naddresses && r == GETDNS_RETURN_GOOD; i++) */

	/* Clean up */
	SSL_CTX_free(ctx);

done_destroy_certificate_authorities:
	if (certificate_authorities)
		X509_STORE_free(certificate_authorities);

done_destroy_response2:
	getdns_dict_destroy(response2);

done_destroy_response:
	getdns_dict_destroy(response);

done_destroy_extensions:
	getdns_dict_destroy(extensions);

done_destroy_context:
	getdns_context_destroy(context);

	return r ? r : (naddresses == nsuccess ? EXIT_SUCCESS : EXIT_FAILURE);
}

#else	/* HAVE_OPENSSL_SSL_H */
int
main(int argc, char *const *argv)
{
	const char *progname = strrchr(argv[0], '/');
	progname = progname ? progname + 1 : argv[0];
	fprintf(stderr, "%s needs OpenSSL support, "
	    "which has not been compiled in.\n", progname);
	return EXIT_FAILURE;
}
#endif	/* HAVE_OPENSSL_SSL_H */

/* tests_dane.c */
