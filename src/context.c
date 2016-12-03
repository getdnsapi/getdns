/**
 *
 * \file context.c
 * @brief getdns context management functions
 *
 * Declarations taken from the getdns API description pseudo implementation.
 *
 */

/*
 * Copyright (c) 2013, NLnet Labs, Verisign, Inc.
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

#ifndef USE_WINSOCK
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#else
#include <winsock2.h>
#include <iphlpapi.h>
typedef unsigned short in_port_t;

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#endif

#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <assert.h>
#include <ctype.h>

#include "config.h"
#ifdef HAVE_LIBUNBOUND
#include <unbound.h>
#endif
#include "debug.h"
#include "gldns/str2wire.h"
#include "gldns/wire2str.h"
#include "context.h"
#include "types-internal.h"
#include "util-internal.h"
#include "dnssec.h"
#include "stub.h"
#include "list.h"
#include "dict.h"
#include "pubkey-pinning.h"

#define GETDNS_PORT_ZERO 0
#define GETDNS_PORT_DNS 53
#define GETDNS_PORT_DNS_OVER_TLS 853
#define GETDNS_STR_PORT_ZERO "0"
#define GETDNS_STR_PORT_DNS "53"
#define GETDNS_STR_PORT_DNS_OVER_TLS "853"

void *plain_mem_funcs_user_arg = MF_PLAIN;

typedef struct host_name_addrs {
	_getdns_rbnode_t node;
	getdns_list *ipv4addrs;
	getdns_list *ipv6addrs;
	uint8_t host_name[];
} host_name_addrs;


/*  If changing these lists also remember to 
    change the value of GETDNS_UPSTREAM_TRANSPORTS */
static getdns_transport_list_t 
getdns_upstream_transports[GETDNS_UPSTREAM_TRANSPORTS] = {
	GETDNS_TRANSPORT_TCP,
	GETDNS_TRANSPORT_TLS,
};

static in_port_t 
getdns_port_array[GETDNS_UPSTREAM_TRANSPORTS] = {
	GETDNS_PORT_DNS,
	GETDNS_PORT_DNS_OVER_TLS
};

static char*
getdns_port_str_array[] = {
	GETDNS_STR_PORT_DNS,
	GETDNS_STR_PORT_DNS_OVER_TLS
};

static const uint8_t no_suffixes[] = { 1, 0 };

/* Private functions */
static getdns_return_t create_default_namespaces(struct getdns_context *context);
static getdns_return_t create_default_dns_transports(struct getdns_context *context);
static int transaction_id_cmp(const void *, const void *);
static void dispatch_updated(struct getdns_context *, uint16_t);
static void cancel_dns_req(getdns_dns_req *);
static void cancel_outstanding_requests(struct getdns_context*, int);

/* unbound helpers */
#ifdef HAVE_LIBUNBOUND
static getdns_return_t rebuild_ub_ctx(struct getdns_context* context);
static void set_ub_string_opt(struct getdns_context *, char *, char *);
static void set_ub_number_opt(struct getdns_context *, char *, uint16_t);
static getdns_return_t set_ub_dns_transport(struct getdns_context*);
static void set_ub_limit_outstanding_queries(struct getdns_context*,
    uint16_t);
static void set_ub_dnssec_allowed_skew(struct getdns_context*, uint32_t);
static void set_ub_edns_maximum_udp_payload_size(struct getdns_context*,
    int);
#endif

/* Stuff to make it compile pedantically */
#define RETURN_IF_NULL(ptr, code) if(ptr == NULL) return code;


#ifdef USE_WINSOCK
/* For windows, the CA trust store is not read by openssl. 
   Add code to open the trust store using wincrypt API and add
   the root certs into openssl trust store */
static int 
add_WIN_cacerts_to_openssl_store(SSL_CTX* tls_ctx)
{
	HCERTSTORE      hSystemStore;
	PCCERT_CONTEXT  pTargetCert = NULL;

	DEBUG_STUB("%s %-35s: %s\n", STUB_DEBUG_SETUP_TLS, __FUNCTION__,
		"Adding Windows certificates to CA store");

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
		DEBUG_STUB("%s %-35s: %s\n", STUB_DEBUG_SETUP_TLS, __FUNCTION__,
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
			DEBUG_STUB("%s %-35s: %s %d:%s\n", STUB_DEBUG_SETUP_TLS, __FUNCTION__,
				"Unable to parse certificate in memory",
				ERR_get_error(), ERR_error_string(ERR_get_error(), NULL));
			return 0;
		}
		else {
			/* return error if a cert add to store fails */
			if (X509_STORE_add_cert(store, cert1) == 0) {
				DEBUG_STUB("%s %-35s: %s %d:%s\n", STUB_DEBUG_SETUP_TLS, __FUNCTION__,
					"Error adding certificate", ERR_get_error(),
					ERR_error_string(ERR_get_error(), NULL));
				return 0;
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
	return 1;
}
#endif

static void destroy_local_host(_getdns_rbnode_t * node, void *arg)
{
	getdns_context *context = (getdns_context *)arg;
	host_name_addrs *hnas = (host_name_addrs *)node;
	getdns_list_destroy(hnas->ipv4addrs);
	getdns_list_destroy(hnas->ipv6addrs);
	GETDNS_FREE(context->my_mf, hnas);
}

/**
 * Helper to get default lookup namespaces.
 * TODO: Determine from OS
 */
static getdns_return_t
create_default_namespaces(struct getdns_context *context)
{
	context->namespaces = GETDNS_XMALLOC(context->my_mf, getdns_namespace_t, 2);
	if(context->namespaces == NULL)
		return GETDNS_RETURN_GENERIC_ERROR;

	context->namespaces[0] = GETDNS_NAMESPACE_LOCALNAMES;
	context->namespaces[1] = GETDNS_NAMESPACE_DNS;
	context->namespace_count = 2;

	return GETDNS_RETURN_GOOD;
}

/**
 * Helper to get default transports.
 */
static getdns_return_t
create_default_dns_transports(struct getdns_context *context)
{
	context->dns_transports = GETDNS_XMALLOC(context->my_mf, getdns_transport_list_t, 2);
	if(context->dns_transports == NULL)
		return GETDNS_RETURN_GENERIC_ERROR;

	context->dns_transports[0] = GETDNS_TRANSPORT_UDP;
	context->dns_transports[1] = GETDNS_TRANSPORT_TCP;
	context->dns_transport_count = 2;
	context->dns_transport_current = 0;

	return GETDNS_RETURN_GOOD;
}

static inline void canonicalize_dname(uint8_t *dname)
{
	uint8_t *next_label;

	while (*dname && !(*dname & 0xC0)) {
		next_label = dname + *dname + 1;
		dname += 1;
		while (dname < next_label) {
			*dname = (uint8_t)tolower((unsigned char)*dname);
			dname++;
		}
	}
}

static int
canonical_dname_compare(register const uint8_t *d1, register const uint8_t *d2)
{
	register uint8_t lab1, lab2;

	assert(d1 && d2);

	lab1 = *d1++;
	lab2 = *d2++;
	while (lab1 != 0 || lab2 != 0) {
		/* compare label length */
		/* if one dname ends, it has labellength 0 */
		if (lab1 != lab2) {
			if (lab1 < lab2)
				return -1;
			return 1;
		}
		while (lab1--) {
			/* compare bytes first for speed */
			if (*d1 != *d2) {
				if (*d1 < *d2)
					return -1;
				return  1;
			}
			d1++;
			d2++;
		}
		/* next pair of labels. */
		lab1 = *d1++;
		lab2 = *d2++;
	}
	return 0;
}

static int
local_host_cmp(const void *id1, const void *id2)
{
	return canonical_dname_compare(id1, id2);
}

/** return 0 on success */
static int
add_local_host(getdns_context *context, getdns_dict *address, const char *str)
{
	uint8_t host_name[256];
	size_t host_name_len = sizeof(host_name);
	host_name_addrs *hnas;
	getdns_bindata *address_type;
	int hnas_found = 0;
	getdns_list **addrs;

	if (gldns_str2wire_dname_buf(str, host_name, &host_name_len))
		return -1;

	canonicalize_dname(host_name);
	
	if (!(hnas = (host_name_addrs *)_getdns_rbtree_search(
	    &context->local_hosts, host_name))) {

		if (!(hnas = (host_name_addrs *)GETDNS_XMALLOC(context->mf,
		    uint8_t, sizeof(host_name_addrs) + host_name_len)))
			return -1;

		hnas->ipv4addrs = NULL;
		hnas->ipv6addrs = NULL;
		(void)memcpy(hnas->host_name, host_name, host_name_len);
		hnas->node.key = &hnas->host_name;

	} else
		hnas_found = 1;
	
	if (getdns_dict_get_bindata(address, "address_type", &address_type) ||

	    address_type->size < 4 ||

	    !(addrs = address_type->data[3] == '4'? &hnas->ipv4addrs
	            : address_type->data[3] == '6'? &hnas->ipv4addrs : NULL)) {

		if (!hnas_found) GETDNS_FREE(context->mf, hnas);
		return -1;
	}
	if (!*addrs && !(*addrs = getdns_list_create_with_context(context))) {
		if (!hnas_found) GETDNS_FREE(context->mf, hnas);
		return -1;
	}
	if (_getdns_list_append_this_dict(*addrs, address)) {
	       	if (!hnas_found) {
			getdns_list_destroy(*addrs);
			GETDNS_FREE(context->mf, hnas);
		}
		return -1;

	} else if (!hnas_found)
		(void)_getdns_rbtree_insert(&context->local_hosts, &hnas->node);

	return 0;
}

static getdns_dict *
sockaddr_dict(getdns_context *context, struct sockaddr *sa)
{
	getdns_dict *address = getdns_dict_create_with_context(context);
	char addrstr[1024], *b;
	getdns_bindata bindata;
	uint16_t port;

	if (!address)
		return NULL;

	switch (sa->sa_family) {
	case AF_INET:
		if (getdns_dict_util_set_string(address,"address_type","IPv4"))
			break;

		bindata.size = 4;
		bindata.data = (void *)&((struct sockaddr_in*)sa)->sin_addr;
		if ((getdns_dict_set_bindata(address,"address_data",&bindata)))
			break;

		port = ntohs(((struct sockaddr_in *)sa)->sin_port);
		if (port != GETDNS_PORT_ZERO && port != GETDNS_PORT_DNS &&
		    getdns_dict_set_int(address, "port", (uint32_t)port))
			break;

		return address;

	case AF_INET6:
		if (getdns_dict_util_set_string(address,"address_type","IPv6"))
			break;

		bindata.size = 16;
		bindata.data = (void *)&((struct sockaddr_in6*)sa)->sin6_addr;
		if ((getdns_dict_set_bindata(address,"address_data",&bindata)))
			break;

		port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
		if (port != GETDNS_PORT_DNS && port != GETDNS_PORT_DNS &&
		    getdns_dict_set_int(address, "port", (uint32_t)port))
			break;

		/* Try to get scope_id too */
		if (getnameinfo(sa, sizeof(struct sockaddr_in6),
		    addrstr, sizeof(addrstr), NULL, 0, NI_NUMERICHOST))
			break;
		if ((b = strchr(addrstr, '%')) &&
		    getdns_dict_util_set_string(address, "scope_id", b+1))
			break;

		return address;
	default:
		/* Unknown protocol */
		break;
	}
	getdns_dict_destroy(address);
	return NULL;
}

static getdns_dict *
str_addr_dict(getdns_context *context, const char *str)
{
	static struct addrinfo hints = { .ai_family = AF_UNSPEC
	                               , .ai_flags  = AI_NUMERICHOST };
	struct addrinfo *ai;
	getdns_dict *address;

	if (getaddrinfo(str, NULL, &hints, &ai))
		return NULL;
	if (!ai)
		return NULL;
		
	address = sockaddr_dict(context, ai->ai_addr);
	freeaddrinfo(ai);

	return address;
}

static void
create_local_hosts(getdns_context *context)
{
	/* enough space in buf for longest allowed domain name */
	char buf[1024];
	char *pos = buf, prev_c, *start_of_word = NULL;
	FILE *in;
	int start_of_line = 1;
	getdns_dict *address = NULL;

#ifdef USE_WINSOCK
	in = fopen("c:\\WINDOWS\\system32\\drivers\\etc\\hosts", "r");
#else
	in = fopen("/etc/hosts", "r");
#endif
	while (fgets(pos, (int)(sizeof(buf) - (pos - buf)), in)) {
		pos = buf;
		/* Break out of for to read more */
		for (;;) {
			/* Skip whitespace */
			while (*pos == ' '  || *pos == '\f' 
			    || *pos == '\t' || *pos == '\v')
				pos++;

			if (*pos == '\0') { /* End of read data */
				pos = buf;
				goto read_more;

			} else if (*pos == '#' || *pos == '\r' || *pos == '\n')
				/* Comments or end of line */
				break; /* skip to next line */

			assert(*pos && !isspace(*pos));

			start_of_word = pos;

			/* Search for end of word */
			while (*pos && !isspace(*pos))
				pos++;

			/* '\0' before whitespace, so either the word did not
			 * fit, or we are at the end of the file.
			 */
			if (*pos == '\0') {
				if (start_of_word == buf) /* word too big */
					break; /* skip to next line */

				/* Move word to fit in buffer */
				memmove(buf,start_of_word,pos - start_of_word);
				pos = buf + (pos - start_of_word);
				start_of_word = buf;
				*pos = '\0';
				goto read_more;
			}
			assert(isspace(*pos));
			prev_c = *pos;
			*pos = '\0';
			if (start_of_line) {
				start_of_line = 0;
				if (address) 
					getdns_dict_destroy(address);
				if (!(address =
				    str_addr_dict(context, start_of_word)))
					/* Unparseable address */
					break; /* skip to next line */
			} else if (!add_local_host(context, address, start_of_word))
				address = NULL;

			start_of_word = NULL;
			*pos = prev_c;
			/* process next word in buf */
		}
		/* skip to next line */
		while (*pos != '\r' && *pos != '\n')
			if (*pos)
				pos++;
			else if (!fgets((pos = buf), sizeof(buf), in))
				break; /* We're done */
		start_of_line = 1;
		if (address) {
			getdns_dict_destroy(address);
			address = NULL;
		}
		pos = buf;
read_more:	;
	}
	fclose(in);
	if (address) {
		/* One last name for this address? */
		if (start_of_word && !start_of_line)
			if (!add_local_host(context, address, start_of_word))
				address = NULL;
		getdns_dict_destroy(address);
	}
}

/**
 * check a file for changes since the last check
 * and refresh the current data if changes are detected
 * @param context pointer to a previously created context to be used for this call
 * @param fchg file to check
 * @returns changes as OR'd list of GETDNS_FCHG_* values
 * @returns GETDNS_FCHG_NONE if no changes
 * @returns GETDNS_FCHG_ERRORS if problems (see fchg->errors for details)
 */
int
_getdns_filechg_check(struct getdns_context *context, struct filechg *fchg)
{
    struct stat *finfo;

    if(fchg == NULL)
        return 0;

    fchg->errors  = GETDNS_FCHG_NOERROR;
    fchg->changes = GETDNS_FCHG_NOCHANGES;

    finfo = GETDNS_MALLOC(context->my_mf, struct stat);
    if(finfo == NULL)
    {
        fchg->errors = errno;
        return GETDNS_FCHG_ERRORS;
	}

    if(stat(fchg->fn, finfo) != 0)
    {
		GETDNS_FREE(context->my_mf, finfo);
        fchg->errors = errno;
        return GETDNS_FCHG_ERRORS;
    }

    /* we want to consider a file that previously returned error for stat() as a
       change */

    if(fchg->prevstat == NULL)
        fchg->changes = GETDNS_FCHG_MTIME | GETDNS_FCHG_CTIME;
    else
    {
        if(fchg->prevstat->st_mtime != finfo->st_mtime)
            fchg->changes |= GETDNS_FCHG_MTIME;
        if(fchg->prevstat->st_ctime != finfo->st_ctime)
            fchg->changes |= GETDNS_FCHG_CTIME;
    	GETDNS_FREE(context->my_mf, fchg->prevstat);
    }
    fchg->prevstat = finfo;

    return fchg->changes;
} /* filechg */

static getdns_upstreams *
upstreams_create(getdns_context *context, size_t size)
{
	getdns_upstreams *r = (void *) GETDNS_XMALLOC(context->mf, char,
	    sizeof(getdns_upstreams) +
	    sizeof(getdns_upstream) * size);
	r->mf = context->mf;
	r->referenced = 1;
	r->count = 0;
	r->current = 0;
	return r;
}

void
_getdns_upstreams_dereference(getdns_upstreams *upstreams)
{
	getdns_upstream *upstream;
	getdns_dns_req *dnsreq;

	if (!upstreams || --upstreams->referenced > 0)
		return;

	for ( upstream = upstreams->upstreams
	    ; upstreams->count
	    ; upstreams->count--, upstream++ ) {

		sha256_pin_t *pin = upstream->tls_pubkey_pinset;
		if (upstream->loop && (   upstream->event.read_cb
		                       || upstream->event.write_cb
		                       || upstream->event.timeout_cb) ) {

			GETDNS_CLEAR_EVENT(upstream->loop, &upstream->event);
			upstream->event.read_cb = NULL;
			upstream->event.write_cb = NULL;
			upstream->event.timeout_cb = NULL;
		}
		if (upstream->loop &&  upstream->finished_event.timeout_cb) {
			GETDNS_CLEAR_EVENT(upstream->loop,
			    &upstream->finished_event);
			upstream->finished_event.timeout_cb = NULL;
		}
		while (upstream->finished_dnsreqs) {
			dnsreq = upstream->finished_dnsreqs;
			upstream->finished_dnsreqs = dnsreq->finished_next;
			(void) _getdns_context_cancel_request(dnsreq->context,
			    dnsreq->trans_id, 1);
		}
		if (upstream->tls_obj != NULL) {
		    if (upstream->tls_session != NULL)
				SSL_SESSION_free(upstream->tls_session);
			SSL_shutdown(upstream->tls_obj);
			SSL_free(upstream->tls_obj);
		}
		if (upstream->fd != -1)
			close(upstream->fd);
		while (pin) {
			sha256_pin_t *nextpin = pin->next;
			GETDNS_FREE(upstreams->mf, pin);
			pin = nextpin;
		}
		upstream->tls_pubkey_pinset = NULL;
	}
	GETDNS_FREE(upstreams->mf, upstreams);
}

#if defined(DAEMON_DEBUG) && DAEMON_DEBUG
static char*
getdns_auth_str_array[] = {
	GETDNS_STR_AUTH_NONE,
	GETDNS_STR_AUTH_FAILED,
	GETDNS_STR_AUTH_OK
};
#endif

void
_getdns_upstream_shutdown(getdns_upstream *upstream)
{
	/*There is a race condition with a new request being scheduled 
	  while this happens so take ownership of the fd asap*/
	int fd = upstream->fd;
	upstream->fd = -1;
	/* If the connection had a problem, but had worked this time,
	 * then allow re-use in the future*/
	if (upstream->tcp.write_error == 1 &&
	    upstream->responses_received > 0)
		upstream->tcp.write_error = 0;
	upstream->writes_done = 0;
	upstream->responses_received = 0;
	upstream->keepalive_timeout = 0;
	if (upstream->tls_hs_state != GETDNS_HS_FAILED) {
		upstream->tls_hs_state = GETDNS_HS_NONE;
		upstream->tls_auth_failed = 0;
	}
	/* Now TLS stuff*/
	if (upstream->tls_obj != NULL) {
		SSL_shutdown(upstream->tls_obj);
		SSL_free(upstream->tls_obj);
		upstream->tls_obj = NULL;
	}
	if (fd != -1)
		close(fd);
}

static int
tls_is_in_transports_list(getdns_context *context) {
	for (int i=0; i< context->dns_transport_count;i++) {
		if (context->dns_transports[i] == GETDNS_TRANSPORT_TLS)
			return 1;
	}
	return 0;
}

static int
tls_only_is_in_transports_list(getdns_context *context) {
	if (context->dns_transport_count != 1)
		return 0;
	if (context->dns_transports[0] == GETDNS_TRANSPORT_TLS)
			return 1;
	return 0;
}


static int
net_req_query_id_cmp(const void *id1, const void *id2)
{
	return (intptr_t)id1 - (intptr_t)id2;
}

static getdns_tsig_info const tsig_info[] = {
	  { GETDNS_NO_TSIG, NULL, 0, NULL, 0, 0, 0 }
	, { GETDNS_HMAC_MD5   , "hmac-md5.sig-alg.reg.int", 24
	       , (uint8_t *)"\x08hmac-md5\x07sig-alg\x03reg\x03int", 26, 10, 16 }
	, { GETDNS_NO_TSIG, NULL, 0, NULL, 0, 0, 0 }
	, { GETDNS_HMAC_SHA1  , "hmac-sha1"  ,  9
	       , (uint8_t *)"\x09hmac-sha1"  , 11, 10, 20 }
	, { GETDNS_HMAC_SHA224, "hmac-sha224", 11
	       , (uint8_t *)"\x0bhmac-sha224", 13, 14, 28 }
	, { GETDNS_HMAC_SHA256, "hmac-sha256", 11
	       , (uint8_t *)"\x0bhmac-sha256", 13, 16, 32 }
	, { GETDNS_HMAC_SHA384, "hmac-sha384", 11
	       , (uint8_t *)"\x0bhmac-sha384", 13, 24, 48 }
	, { GETDNS_HMAC_SHA512, "hmac-sha512", 11
	       , (uint8_t *)"\x0bhmac-sha512", 13, 32, 64 }
	, { GETDNS_HMAC_MD5   , "hmac-md5"   ,  8
	       , (uint8_t *)"\x08hmac-md5"   , 10, 10, 16 }
};
static size_t const n_tsig_infos =
    sizeof(tsig_info) / sizeof(getdns_tsig_info);

static getdns_tsig_info const * const last_tsig_info =
    tsig_info + (sizeof(tsig_info) / sizeof(getdns_tsig_info));

const getdns_tsig_info *_getdns_get_tsig_info(getdns_tsig_algo tsig_alg)
{
	return tsig_alg > n_tsig_infos - 1
	    || tsig_info[tsig_alg].alg == GETDNS_NO_TSIG ? NULL
	    : &tsig_info[tsig_alg];
}

static getdns_tsig_algo _getdns_get_tsig_algo(getdns_bindata *algo)
{
	const getdns_tsig_info *i;

	if (!algo || algo->size == 0)
		return GETDNS_NO_TSIG;

	if (algo->data[algo->size-1] != 0) {
		/* Unterminated string */
		for (i = tsig_info; i < last_tsig_info; i++)
			if ((algo->size == i->strlen_name ||
			     (algo->size - 1 == i->strlen_name &&
			      algo->data[algo->size - 1] == '.'
			     )
			    )&&
			    strncasecmp((const char *)algo->data, i->name,
			    i->strlen_name) == 0)
				return i->alg;
		
	} else if (!_getdns_bindata_is_dname(algo)) {
		/* Terminated string */
		for (i = tsig_info; i < last_tsig_info; i++)
			if (algo->size - 1 == i->strlen_name &&
			    strncasecmp((const char *)algo->data, i->name,
			    i->strlen_name) == 0)
				return i->alg;

	} else {
		/* fqdn, canonical_dname_compare is now safe to use! */
		for (i = tsig_info; i < last_tsig_info; i++)
			if (canonical_dname_compare(algo->data, i->dname) == 0)
				return i->alg;
	}
	return GETDNS_NO_TSIG;
}

static void
upstream_init(getdns_upstream *upstream,
    getdns_upstreams *parent, struct addrinfo *ai)
{
	upstream->upstreams = parent;

	upstream->addr_len = ai->ai_addrlen;
	(void) memcpy(&upstream->addr, ai->ai_addr, ai->ai_addrlen);

	/* How is this upstream doing? */
	upstream->writes_done = 0;
	upstream->responses_received = 0;
	upstream->keepalive_timeout = 0;
	upstream->to_retry =  2;
	upstream->back_off =  1;

	/* For sharing a socket to this upstream with TCP  */
	upstream->fd       = -1;
	upstream->tls_obj  = NULL;
	upstream->tls_session = NULL;
	upstream->transport = GETDNS_TRANSPORT_TCP;
	upstream->tls_hs_state = GETDNS_HS_NONE;
	upstream->tls_auth_failed = 0;
	upstream->tls_auth_name[0] = '\0';
	upstream->tls_pubkey_pinset = NULL;
	upstream->tcp.write_error = 0;
	upstream->loop = NULL;
	(void) getdns_eventloop_event_init(
	    &upstream->event, upstream, NULL, NULL, NULL);
	(void) memset(&upstream->tcp, 0, sizeof(upstream->tcp));

	upstream->write_queue = NULL;
	upstream->write_queue_last = NULL;

	upstream->finished_dnsreqs = NULL;
	(void) getdns_eventloop_event_init(
	    &upstream->finished_event, upstream, NULL, NULL, NULL);

	upstream->has_client_cookie = 0;
	upstream->has_prev_client_cookie = 0;
	upstream->has_server_cookie = 0;

	upstream->tsig_alg  = GETDNS_NO_TSIG;
	upstream->tsig_dname_len = 0;
	upstream->tsig_size = 0;

	/* Tracking of network requests on this socket */
	_getdns_rbtree_init(&upstream->netreq_by_query_id,
	    net_req_query_id_cmp);
}

#ifdef USE_WINSOCK

/*
Read the Windows search suffix and add to context
There may or may not be domains and suffixes so do not error if missing
*/
static int get_dns_suffix_windows(getdns_list *suffix, char* domain)
{
    char *parse, *token, prev_ch;
    char lszValue[255] = "";
    char lszDomain[255] = "";
    HKEY hKey;
    LONG returnStatus;
    DWORD dwType=REG_SZ;
    DWORD dwSize=255;
    returnStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Services\\TcpIp\\Parameters",
                     0,  KEY_READ, &hKey);
    if (returnStatus != ERROR_SUCCESS)
    {
        /* try windows 9x/me */
        returnStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Services\\VxD\\MSTCP",
                     0,  KEY_READ, &hKey);

    }
    if (returnStatus == ERROR_SUCCESS)
    {
        returnStatus = RegQueryValueEx(hKey,
             TEXT("SearchList"), 0, &dwType,(LPBYTE)&lszValue, &dwSize);
        if (returnStatus == ERROR_SUCCESS) 
        {
           if ((strlen(lszValue)) > 0) {
           parse = lszValue;
           do {
               parse += strspn(parse, ",");
               token = parse + strcspn(parse, ",");
               prev_ch = *token;
               *token = 0;
               _getdns_list_append_string(suffix, parse);

               *token = prev_ch;
               parse = token;
           } while (*parse);
           }

        }

        dwSize = 255;
        returnStatus = RegQueryValueEx(hKey,
             TEXT("Domain"), 0, &dwType,(LPBYTE)&lszDomain, &dwSize);
        if (returnStatus == ERROR_SUCCESS)
        {
             strcpy_s(domain, dwSize, lszDomain);
        }

        RegCloseKey(hKey);
    } else {
        return 0; /* no DNS keys or suffixes */
    }

    return 1;
}


static getdns_return_t
set_os_defaults_windows(struct getdns_context *context)
{
    char domain[1024] = "";
    size_t upstreams_limit = 10;
    struct addrinfo hints;
    struct addrinfo *result;
    getdns_list *suffix;
    getdns_upstream *upstream;
    size_t length;
    int s;

    if (context->fchg_resolvconf == NULL) {
		context->fchg_resolvconf =
			GETDNS_MALLOC(context->my_mf, struct filechg);
		if (context->fchg_resolvconf == NULL)
			return GETDNS_RETURN_MEMORY_ERROR;
		context->fchg_resolvconf->fn = "InvalidOnWindows";
		context->fchg_resolvconf->prevstat = NULL;
		context->fchg_resolvconf->changes = GETDNS_FCHG_NOCHANGES;
		context->fchg_resolvconf->errors = GETDNS_FCHG_NOERROR;
    }
    _getdns_filechg_check(context, context->fchg_resolvconf);

    context->upstreams = upstreams_create(context, upstreams_limit);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
    hints.ai_socktype = 0;              /* Datagram socket */
    hints.ai_flags = AI_NUMERICHOST; /* No reverse name lookups */
    hints.ai_protocol = 0;              /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    FIXED_INFO *info;
    ULONG buflen = sizeof(*info);
    IP_ADDR_STRING *ptr = 0;

    info = (FIXED_INFO *)malloc(sizeof(FIXED_INFO));
    if (info == NULL)
		return GETDNS_RETURN_GENERIC_ERROR;

    if (GetNetworkParams(info, &buflen) == ERROR_BUFFER_OVERFLOW) {
		free(info);
		info = (FIXED_INFO *)malloc(buflen);
		if (info == NULL)
			return GETDNS_RETURN_GENERIC_ERROR;
	}

	if (GetNetworkParams(info, &buflen) == NO_ERROR) {
		ptr = info->DnsServerList.Next; 
		*domain = 0;
		while (ptr) {
			for (size_t i = 0; i < GETDNS_UPSTREAM_TRANSPORTS; i++) {
				char *port_str = getdns_port_str_array[i];
				if ((s = getaddrinfo(ptr->IpAddress.String, port_str, &hints, &result)))
					continue;
				if (!result)
					continue;

				upstream = &context->upstreams->
					upstreams[context->upstreams->count++];
				upstream_init(upstream, context->upstreams, result);
				upstream->transport = getdns_upstream_transports[i];
				freeaddrinfo(result);
			}
			ptr = ptr->Next;

		}
		free(info);
	}

    suffix = getdns_list_create_with_context(context);

    if (get_dns_suffix_windows(suffix, domain)) {
        (void) getdns_list_get_length(suffix, &length);
        if (*domain != 0) {
            _getdns_list_append_string(suffix, domain);
        }
        (void) getdns_list_get_length(suffix, &length);
        if (length > 0) {
            (void )getdns_context_set_suffix(context, suffix);
        }
    }
    getdns_list_destroy(suffix);

    return GETDNS_RETURN_GOOD;
} /* set_os_defaults_windows */

#else

static getdns_return_t
set_os_defaults(struct getdns_context *context)
{
	FILE *in;
	char line[1024], domain[1024];
	char *parse, *token, prev_ch;
	size_t upstream_count, length;
	struct addrinfo hints;
	struct addrinfo *result;
	getdns_upstream *upstream;
	getdns_list     *suffix;
	int s;

	if(context->fchg_resolvconf == NULL) {
		context->fchg_resolvconf =
		    GETDNS_MALLOC(context->my_mf, struct filechg);
		if(context->fchg_resolvconf == NULL)
			return GETDNS_RETURN_MEMORY_ERROR;
		context->fchg_resolvconf->fn       = "/etc/resolv.conf";
		context->fchg_resolvconf->prevstat = NULL;
		context->fchg_resolvconf->changes  = GETDNS_FCHG_NOCHANGES;
		context->fchg_resolvconf->errors   = GETDNS_FCHG_NOERROR;
	}
	_getdns_filechg_check(context, context->fchg_resolvconf);

	in = fopen(context->fchg_resolvconf->fn, "r");
	if (!in)
		return GETDNS_RETURN_GOOD;

	upstream_count = 0;
	while (fgets(line, (int)sizeof(line), in))
		if (strncmp(line, "nameserver", 10) == 0)
			upstream_count++;
	fclose(in);

	suffix = getdns_list_create_with_context(context);
	context->upstreams = upstreams_create(
	    context, upstream_count * GETDNS_UPSTREAM_TRANSPORTS);

	in = fopen(context->fchg_resolvconf->fn, "r");
	if (!in)
		return GETDNS_RETURN_GOOD;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
	hints.ai_socktype  = 0;              /* Datagram socket */
	hints.ai_flags     = AI_NUMERICHOST; /* No reverse name lookups */
	hints.ai_protocol  = 0;              /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr      = NULL;
	hints.ai_next      = NULL;

	*domain = 0;
	while (fgets(line, (int)sizeof(line), in)) {
		line[sizeof(line)-1] = 0;
		/* parse = line + strspn(line, " \t"); */ /* No leading whitespace */
		parse = line;

		if (strncmp(parse, "domain", 6) == 0) {
			parse += 6;
			parse += strspn(parse, " \t");
			if (*parse == 0 || *parse == '#') continue;
			token = parse + strcspn(parse, " \t\r\n");
			*token = 0;

			(void) strlcpy(domain, parse, sizeof(domain));
			continue;
		}
		if (strncmp(parse, "search", 6) == 0) {
			parse += 6;
			do {
				parse += strspn(parse, " \t");
				if (*parse == '#' || *parse == '\n') break;
				token = parse + strcspn(parse, " \t\r\n");
				prev_ch = *token;
				*token = 0;

				_getdns_list_append_string(suffix, parse);

				*token = prev_ch;
				parse = token;
			} while (*parse);
			continue;
		}
		if (strncmp(parse, "nameserver", 10) != 0)
			continue;

		parse += 10;
		parse += strspn(parse, " \t");
		if (*parse == 0 || *parse == '#') continue;
		token = parse + strcspn(parse, " \t\r\n");
		*token = 0;

		for (size_t i = 0; i < GETDNS_UPSTREAM_TRANSPORTS; i++) {
			char *port_str = getdns_port_str_array[i];
			if ((s = getaddrinfo(parse, port_str, &hints, &result)))
				continue;
			if (!result)
				continue;

			upstream = &context->upstreams->
			    upstreams[context->upstreams->count++];
			upstream_init(upstream, context->upstreams, result);
			upstream->transport = getdns_upstream_transports[i];
			freeaddrinfo(result);
		}
	}
	fclose(in);

	(void) getdns_list_get_length(suffix, &length);
	if (length == 0 && *domain != 0)
		_getdns_list_append_string(suffix, domain);
	(void )getdns_context_set_suffix(context, suffix);
	getdns_list_destroy(suffix);

	return GETDNS_RETURN_GOOD;
} /* set_os_defaults */
#endif

/* compare of transaction ids in DESCENDING order
   so that 0 comes last
*/
static int
transaction_id_cmp(const void *id1, const void *id2)
{
    if (id1 == NULL && id2 == NULL) {
        return 0;
    } else if (id1 == NULL && id2 != NULL) {
        return 1;
    } else if (id1 != NULL && id2 == NULL) {
        return -1;
    } else {
        getdns_transaction_t t1 =
            *((const getdns_transaction_t *) id1);
        getdns_transaction_t t2 =
            *((const getdns_transaction_t *) id2);
        if (t1 == t2) {
            return 0;
        } else if (t1 > t2) {
            return -1;
        } else {
            return 1;
        }
    }
}

static void
NULL_update_callback(
    getdns_context *context, getdns_context_code_t code, void *userarg)
{ (void)context; (void)code; (void)userarg; }

/*
 * getdns_context_create
 *
 * Call this to initialize the context that is used in other getdns calls.
 */
getdns_return_t
getdns_context_create_with_extended_memory_functions(
    struct getdns_context ** context,
    int set_from_os,
    void *userarg,
    void *(*malloc)(void *userarg, size_t),
    void *(*realloc)(void *userarg, void *, size_t),
    void (*free)(void *userarg, void *)
    )
{
	getdns_return_t r;
	struct getdns_context *result = NULL;
	mf_union mf;
	gldns_buffer gbuf;
#ifdef USE_WINSOCK
	WORD wVersionRequested;
#endif

	if (!context || !malloc || !realloc || !free)
		return GETDNS_RETURN_INVALID_PARAMETER;

	/** default init **/
	mf.ext.malloc = malloc;
	result = userarg == MF_PLAIN
	    ? (*mf.pln.malloc)(         sizeof(struct getdns_context))
	    : (*mf.ext.malloc)(userarg, sizeof(struct getdns_context));

	if (!result)
		return GETDNS_RETURN_MEMORY_ERROR;

#ifdef USE_WINSOCK
	/* We need to run WSAStartup() to be able to use getaddrinfo() */
	wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &result->wsaData)) {
		r = GETDNS_RETURN_GENERIC_ERROR;
		goto error;
	}
#endif
	result->processing = 0;
	result->destroying = 0;
	result->my_mf.mf_arg         = userarg;
	result->my_mf.mf.ext.malloc  = malloc;
	result->my_mf.mf.ext.realloc = realloc;
	result->my_mf.mf.ext.free    = free;

	result->update_callback  = NULL;
	result->update_callback2 = NULL_update_callback;
	result->update_userarg   = NULL;

	result->mf.mf_arg         = userarg;
	result->mf.mf.ext.malloc  = malloc;
	result->mf.mf.ext.realloc = realloc;
	result->mf.mf.ext.free    = free;

	result->resolution_type_set = 0;

	_getdns_rbtree_init(&result->outbound_requests, transaction_id_cmp);
	_getdns_rbtree_init(&result->local_hosts, local_host_cmp);

#ifdef HAVE_LIBUNBOUND
	result->resolution_type = GETDNS_RESOLUTION_RECURSING;
#else
	result->resolution_type = GETDNS_RESOLUTION_STUB;
#endif
	if ((r = create_default_namespaces(result)))
		goto error;

	result->timeout = 5000;
	result->idle_timeout = 0;
	result->follow_redirects = GETDNS_REDIRECTS_FOLLOW;
	result->dns_root_servers = NULL;
#if defined(HAVE_LIBUNBOUND) && !defined(HAVE_UB_CTX_SET_STUB)
	result->root_servers_fn[0] = 0;
#endif
	result->append_name = GETDNS_APPEND_NAME_TO_SINGLE_LABEL_FIRST;
	result->suffixes = no_suffixes;
	result->suffixes_len = sizeof(no_suffixes);

	gldns_buffer_init_frm_data(&gbuf, result->trust_anchors_spc
	                                , sizeof(result->trust_anchors_spc));

	if (!_getdns_parse_ta_file(NULL, &gbuf)) {
		result->trust_anchors = NULL;
		result->trust_anchors_len = 0;

	} else if ((result->trust_anchors_len = gldns_buffer_position(&gbuf))
		    > sizeof(result->trust_anchors_spc)) {

		if ((result->trust_anchors = GETDNS_XMALLOC(
		    result->mf, uint8_t, result->trust_anchors_len))) {

			gldns_buffer_init_frm_data(&gbuf
			                          , result->trust_anchors
						  , result->trust_anchors_len);
			if (!_getdns_parse_ta_file(NULL, &gbuf)) {
				result->trust_anchors = NULL;
				result->trust_anchors_len = 0;
			}
		}
	} else
		result->trust_anchors = result->trust_anchors_spc;

	result->upstreams = NULL;

	result->edns_extended_rcode = 0;
	result->edns_version = 0;
	result->edns_do_bit = 0;
	result->edns_client_subnet_private = 0;
	result->tls_query_padding_blocksize = 1; /* default is to not try to pad */
	result->tls_ctx = NULL;

	result->extension = &result->default_eventloop.loop;
	_getdns_default_eventloop_init(&result->default_eventloop);
	_getdns_default_eventloop_init(&result->sync_eventloop);

	result->fchg_resolvconf = NULL;
	result->fchg_hosts      = NULL;

	// resolv.conf does not exist on Windows, handle differently
#ifndef USE_WINSOCK 
	if ((set_from_os & 1) && (r = set_os_defaults(result)))
		goto error;
#else
	if ((set_from_os & 1) && (r = set_os_defaults_windows(result)))
		goto error;
#endif

	result->dnssec_allowed_skew = 0;
	result->edns_maximum_udp_payload_size = -1;
	if ((r = create_default_dns_transports(result)))
		goto error;
	result->tls_auth = GETDNS_AUTHENTICATION_NONE; 
	result->tls_auth_min = GETDNS_AUTHENTICATION_NONE;
	result->limit_outstanding_queries = 0;
	result->return_dnssec_status = GETDNS_EXTENSION_FALSE;

	/* unbound context is initialized here */
	/* Unbound needs SSL to be init'ed this early when TLS is used. However we
	 * don't know that till later so we will have to do this every time. */

	if ((set_from_os & 2) == 0)
		SSL_library_init();

#ifdef HAVE_LIBUNBOUND
	result->unbound_ctx = NULL;
	if ((r = rebuild_ub_ctx(result)))
		goto error;
#endif

	create_local_hosts(result);

	*context = result;
	return GETDNS_RETURN_GOOD;
error:
	getdns_context_destroy(result);
	return r;
} /* getdns_context_create_with_extended_memory_functions */

/*
 * getdns_context_create
 *
 * Call this to initialize the context that is used in other getdns calls.
 */
getdns_return_t
getdns_context_create_with_memory_functions(struct getdns_context ** context,
    int set_from_os,
    void *(*malloc)(size_t),
    void *(*realloc)(void *, size_t),
    void (*free)(void *)
    )
{
    mf_union mf;
    mf.pln.malloc = malloc;
    mf.pln.realloc = realloc;
    mf.pln.free = free;
    return getdns_context_create_with_extended_memory_functions(
        context, set_from_os, MF_PLAIN,
        mf.ext.malloc, mf.ext.realloc, mf.ext.free);
}               /* getdns_context_create */

/*
 * getdns_context_create
 *
 * Call this to initialize the context that is used in other getdns calls.
 */
getdns_return_t
getdns_context_create(struct getdns_context ** context, int set_from_os)
{
    return getdns_context_create_with_memory_functions(context,
            set_from_os, malloc, realloc, free);
}               /* getdns_context_create */


/*
 * getdns_context_destroy
 *
 * Call this to dispose of resources associated with a context once you
 * are done with it.
 */
void
getdns_context_destroy(struct getdns_context *context)
{
	if (context == NULL)
		return;

	/*  If being destroyed during getdns callback, fail via assert */
	assert(context->processing == 0);
	if (context->destroying)
		return;

	context->destroying = 1;
	/* cancel all outstanding requests */
	cancel_outstanding_requests(context, 1);

	/* This needs to be done before cleaning the extension, because there
	 * might be an idle_timeout schedules, which will not get unscheduled
	 * with cancel_outstanding_requests.
	 */
	_getdns_upstreams_dereference(context->upstreams);

	context->sync_eventloop.loop.vmt->cleanup(&context->sync_eventloop.loop);
	context->extension->vmt->cleanup(context->extension);
#ifdef HAVE_LIBUNBOUND
	if (context->unbound_ctx)
		ub_ctx_delete(context->unbound_ctx);
#endif

	if (context->namespaces)
		GETDNS_FREE(context->my_mf, context->namespaces);

	if (context->dns_transports)
		GETDNS_FREE(context->my_mf, context->dns_transports);

	if(context->fchg_resolvconf) {
		if(context->fchg_resolvconf->prevstat)
			GETDNS_FREE(context->my_mf, context->fchg_resolvconf->prevstat);
		GETDNS_FREE(context->my_mf, context->fchg_resolvconf);
	}
	if(context->fchg_hosts) {
		if(context->fchg_hosts->prevstat)
			GETDNS_FREE(context->my_mf, context->fchg_hosts->prevstat);
		GETDNS_FREE(context->my_mf, context->fchg_hosts);
	}
	if (context->tls_ctx)
		SSL_CTX_free(context->tls_ctx);

	if (context->dns_root_servers)
		getdns_list_destroy(context->dns_root_servers);

#if defined(HAVE_LIBUNBOUND) && !defined(HAVE_UB_CTX_SET_STUB)
	if (context->root_servers_fn[0])
		unlink(context->root_servers_fn);
#endif

	if (context->suffixes && context->suffixes != no_suffixes)
		GETDNS_FREE(context->mf, (void *)context->suffixes);

	if (context->trust_anchors &&
	    context->trust_anchors != context->trust_anchors_spc)
		GETDNS_FREE(context->mf, context->trust_anchors);

	_getdns_traverse_postorder(&context->local_hosts,
	    destroy_local_host, context);

#ifdef USE_WINSOCK
	WSACleanup();
#endif
	GETDNS_FREE(context->my_mf, context);
}               /* getdns_context_destroy */

/*
 * getdns_context_set_context_update_callback
 *
 */
getdns_return_t
getdns_context_set_context_update_callback(struct getdns_context *context,
    void (*value) (struct getdns_context *context,
                   getdns_context_code_t changed_item))
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    context->update_callback = value;
    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_context_update_callback */

getdns_return_t
getdns_context_set_update_callback(getdns_context *context, void *userarg,
    void (*cb)(getdns_context *, getdns_context_code_t, void *))
{
	if (!context) return GETDNS_RETURN_INVALID_PARAMETER;
	context->update_userarg = userarg;
	context->update_callback2 = cb ? cb : NULL_update_callback;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_update_callback(getdns_context *context, void **userarg,
    void (**cb)(getdns_context *, getdns_context_code_t, void *))
{
	if (!context || !userarg || !cb)
		return GETDNS_RETURN_INVALID_PARAMETER;

	*userarg = context->update_userarg;
	*cb = context->update_callback2;
	return GETDNS_RETURN_GOOD;
}

#ifdef HAVE_LIBUNBOUND
/*
 * Helpers to set options on the unbound ctx
 */
static void
set_ub_string_opt(struct getdns_context *ctx, char *opt, char *value)
{
    if (ctx->unbound_ctx)
        ub_ctx_set_option(ctx->unbound_ctx, opt, value);
}

static void
set_ub_number_opt(struct getdns_context *ctx, char *opt, uint16_t value)
{
    char buffer[64];
    snprintf(buffer, 64, "%hu", value);
    set_ub_string_opt(ctx, opt, buffer);
}

static void
getdns_context_request_count_changed(getdns_context *context)
{
	size_t prev_count;

	if (context->ub_event_scheduling) {
		return;
	}
	context->ub_event_scheduling++;
	do {
		prev_count = context->outbound_requests.count;
		DEBUG_SCHED("getdns_context_request_count_changed(%d)\n",
		    (int) context->outbound_requests.count);
		if (context->outbound_requests.count && ! context->ub_event.ev){
			DEBUG_SCHED("gc_request_count_changed "
			    "-> ub schedule(el_ev = %p, el_ev->ev = %p)\n",
			    &context->ub_event, context->ub_event.ev);
#ifndef USE_WINSOCK
#ifdef HAVE_UNBOUND_EVENT_API
			if (!_getdns_ub_loop_enabled(&context->ub_loop))
#endif
				context->extension->vmt->schedule(
				    context->extension,
				    ub_fd(context->unbound_ctx),
				    TIMEOUT_FOREVER, &context->ub_event);
#endif
		} else if (! context->outbound_requests.count &&
		    context->ub_event.ev) {
			DEBUG_SCHED("gc_request_count_changed "
			    "-> ub clear(el_ev = %p, el_ev->ev = %p)\n",
			    &context->ub_event, context->ub_event.ev);

#ifndef USE_WINSOCK
#ifdef HAVE_UNBOUND_EVENT_API
			if (!_getdns_ub_loop_enabled(&context->ub_loop))
#endif
				context->extension->vmt->clear(
				    context->extension, &context->ub_event);
#endif
		}
	} while (prev_count != context->outbound_requests.count);
	context->ub_event_scheduling--;
}

void
_getdns_context_ub_read_cb(void *userarg)
{
	getdns_context *context = (getdns_context *)userarg;

	/* getdns_context_process_async, but without reinvoking an eventloop
	 * (with context->extension->vmt->run*), because we are already
	 * called from a running eventloop.
	 */
	if (ub_poll(context->unbound_ctx))
		(void) ub_process(context->unbound_ctx);

	/* No need to handle timeouts. They are handled by the extension. */

	getdns_context_request_count_changed(context);
}

static getdns_return_t
rebuild_ub_ctx(struct getdns_context* context) {
	if (context->unbound_ctx != NULL) {
		/* cancel all requests and delete */
		cancel_outstanding_requests(context, 1);
		ub_ctx_delete(context->unbound_ctx);
		context->unbound_ctx = NULL;
	}
	/* setup */
#ifdef HAVE_UNBOUND_EVENT_API
	_getdns_ub_loop_init(&context->ub_loop, &context->mf, context->extension);
	if (_getdns_ub_loop_enabled(&context->ub_loop)) {
		context->unbound_ctx = ub_ctx_create_ub_event(&context->ub_loop.super);
	} else {
#endif
		context->unbound_ctx = ub_ctx_create();
		(void) ub_ctx_async(context->unbound_ctx, 1);
#ifdef HAVE_UNBOUND_EVENT_API
	}
#endif
	context->unbound_ta_set = 0;
	if (!context->unbound_ctx)
		return GETDNS_RETURN_MEMORY_ERROR;

#ifdef HAVE_UNBOUND_EVENT_API
        ub_ctx_set_option(context->unbound_ctx,
	    "target-fetch-policy:", "0 0 0 0 0");
#endif
	set_ub_dnssec_allowed_skew(context,
		context->dnssec_allowed_skew);
	set_ub_edns_maximum_udp_payload_size(context,
		context->edns_maximum_udp_payload_size);
	set_ub_dns_transport(context);

	context->ub_event.userarg    = context;
	context->ub_event.read_cb    = _getdns_context_ub_read_cb;
	context->ub_event.write_cb   = NULL;
	context->ub_event.timeout_cb = NULL;
	context->ub_event.ev         = NULL;
	context->ub_event_scheduling = 0;

	return GETDNS_RETURN_GOOD;
}
#else
#define set_ub_string_opt(ctx, opt, value) do {} while (0)
#define set_ub_number_opt(ctx, opt, value) do {} while (0)
#define getdns_context_request_count_changed(context) do {} while (0)
#endif

/**
 * Helper to dispatch the updated callback
 */
static void
dispatch_updated(struct getdns_context *context, uint16_t item)
{
	if (context->update_callback2 != NULL_update_callback)
		context->update_callback2(
		    context, item, context->update_userarg);

    if (context->update_callback) {
        context->update_callback(context, item);
    }
}

/*
 * getdns_context_set_resolution_type
 *
 */
getdns_return_t
getdns_context_set_resolution_type(struct getdns_context *context,
    getdns_resolution_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (value != GETDNS_RESOLUTION_STUB && value != GETDNS_RESOLUTION_RECURSING) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
#ifndef HAVE_LIBUNBOUND
    if (value == GETDNS_RESOLUTION_RECURSING)
	    return GETDNS_RETURN_NOT_IMPLEMENTED;
#endif
#ifndef STUB_NATIVE_DNSSEC
    if (context->resolution_type_set != 0) {
        /* already setup */
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
#endif
    context->resolution_type = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_RESOLUTION_TYPE);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_resolution_type */

/*
 * getdns_context_set_namespaces
 *
 */
getdns_return_t
getdns_context_set_namespaces(getdns_context *context,
    size_t namespace_count, getdns_namespace_t *namespaces)
{
	size_t i;
	getdns_return_t r = GETDNS_RETURN_GOOD;

	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (namespace_count == 0 || namespaces == NULL)
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;

	for (i = 0; i < namespace_count; i++) {
		if (namespaces[i] == GETDNS_NAMESPACE_NETBIOS ||
		    namespaces[i] == GETDNS_NAMESPACE_MDNS ||
		    namespaces[i] == GETDNS_NAMESPACE_NIS)
			r = GETDNS_RETURN_NOT_IMPLEMENTED;

		else if (namespaces[i] != GETDNS_NAMESPACE_DNS &&
		    namespaces[i] != GETDNS_NAMESPACE_LOCALNAMES)
			return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}
	GETDNS_FREE(context->my_mf, context->namespaces);

	/** duplicate **/
	context->namespaces = GETDNS_XMALLOC(
	    context->my_mf, getdns_namespace_t, namespace_count);
	(void) memcpy(context->namespaces, namespaces,
	    namespace_count * sizeof(getdns_namespace_t));
	context->namespace_count = namespace_count;

	dispatch_updated(context, GETDNS_CONTEXT_CODE_NAMESPACES);

	return r;
}               /* getdns_context_set_namespaces */

static getdns_return_t
getdns_set_base_dns_transports(
    getdns_context *context, size_t transport_count, getdns_transport_list_t *transports)
{
	size_t i;
	getdns_transport_list_t *new_transports;

	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
	if (transport_count == 0 || !transports)
		return GETDNS_RETURN_INVALID_PARAMETER;

	/* Check for valid transports and that they are used only once*/
	int u=0,t=0,l=0;
	for(i=0; i<transport_count; i++)
	{
		switch (transports[i]) {
			case GETDNS_TRANSPORT_UDP:       u++; break;
			case GETDNS_TRANSPORT_TCP:       t++; break;
			case GETDNS_TRANSPORT_TLS:       l++; break;
			default: return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
		}
	}
	if ( u>1 || t>1 || l>1)
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	
	if (!(new_transports = GETDNS_XMALLOC(context->my_mf,
		getdns_transport_list_t, transport_count)))
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;

	if (context->dns_transports)
		GETDNS_FREE(context->my_mf, context->dns_transports);

	/** duplicate **/
	context->dns_transports = new_transports;
	memcpy(context->dns_transports, transports,
	    transport_count * sizeof(getdns_transport_list_t));
	context->dns_transport_count = transport_count;

	return GETDNS_RETURN_GOOD;
}

static getdns_return_t
set_ub_dns_transport(struct getdns_context* context) {
    /* These mappings are not exact because Unbound is configured differently,
       so just map as close as possible. Not all options can be supported.*/
    switch (context->dns_transports[0]) {
        case GETDNS_TRANSPORT_UDP:
            set_ub_string_opt(context, "do-udp:", "yes");
            if (context->dns_transport_count > 1
	        && context->dns_transports[1] == GETDNS_TRANSPORT_TCP)
                set_ub_string_opt(context, "do-tcp:", "yes");
            else
                set_ub_string_opt(context, "do-tcp:", "no");
            break;
        case GETDNS_TRANSPORT_TCP:
            set_ub_string_opt(context, "do-udp:", "no");
            set_ub_string_opt(context, "do-tcp:", "yes");
            break;
        case GETDNS_TRANSPORT_TLS:
            set_ub_string_opt(context, "do-udp:", "no");
            set_ub_string_opt(context, "do-tcp:", "yes");
            /* Find out if there is a fallback available. */
            int fallback = 0;
            for (size_t i = 1; i < context->dns_transport_count; i++) {
                if (context->dns_transports[i] == GETDNS_TRANSPORT_TCP) {
                    fallback = 1;
                    break;
                }
                else if (context->dns_transports[i] == GETDNS_TRANSPORT_UDP) {
                    set_ub_string_opt(context, "do-udp:", "yes");
                    set_ub_string_opt(context, "do-tcp:", "no");
                    fallback = 1;
                    break;
                }
            }
            if (fallback == 0) 
                /* Use TLS if it is the only thing.*/
                set_ub_string_opt(context, "ssl-upstream:", "yes");
            break;
       default:
           return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
        }
    return GETDNS_RETURN_GOOD;
}

/*
 * getdns_context_set_dns_transport
 *
 */
getdns_return_t
getdns_context_set_dns_transport(
    getdns_context *context, getdns_transport_t value)
{
	size_t count = 2;
	getdns_transport_list_t *new_transports;

	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);

	if (value == GETDNS_TRANSPORT_UDP_ONLY ||
	    value == GETDNS_TRANSPORT_TCP_ONLY ||
	    value == GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN ||
	    value == GETDNS_TRANSPORT_TLS_ONLY_KEEP_CONNECTIONS_OPEN)
	    count = 1;

	if (!(new_transports = GETDNS_XMALLOC(
	       context->my_mf, getdns_transport_list_t, count)))
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;

	if (context->dns_transports)
		GETDNS_FREE(context->my_mf, context->dns_transports);

	context->dns_transport_count = count;
	context->dns_transports = new_transports;

	switch ((int)value) {
	    case GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP:
	        context->dns_transports[0] = GETDNS_TRANSPORT_UDP;
	        context->dns_transports[1] = GETDNS_TRANSPORT_TCP;
	        break;
	    case GETDNS_TRANSPORT_UDP_ONLY:
	        context->dns_transports[0] = GETDNS_TRANSPORT_UDP;
	        break;
	    case GETDNS_TRANSPORT_TCP_ONLY:
	    case GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN:
	        context->dns_transports[0] = GETDNS_TRANSPORT_TCP;
	        break;
	    case GETDNS_TRANSPORT_TLS_ONLY_KEEP_CONNECTIONS_OPEN:
	        context->dns_transports[0] = GETDNS_TRANSPORT_TLS;
	        break;
	    case GETDNS_TRANSPORT_TLS_FIRST_AND_FALL_BACK_TO_TCP_KEEP_CONNECTIONS_OPEN:
	        context->dns_transports[0] = GETDNS_TRANSPORT_TLS;
	        context->dns_transports[1] = GETDNS_TRANSPORT_TCP;
	       break;
	   default:
	       return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}
	/* Note that the call below does not have any effect in unbound after the
	 * ctx is finalised so for recursive mode or stub + dnssec only the first
	 * transport specified on the first query is used.
	 * However the method returns success as otherwise the transport could not
	 * be reset for stub mode.
	 * Also, not all transport options supported in libunbound yet */
	if (set_ub_dns_transport(context) != GETDNS_RETURN_GOOD) {
	    return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}
	dispatch_updated(context, GETDNS_CONTEXT_CODE_DNS_TRANSPORT);
	return GETDNS_RETURN_GOOD;
}

/*
 * getdns_context_set_dns_transport_list
 *
 */
getdns_return_t
getdns_context_set_dns_transport_list(getdns_context *context,
    size_t transport_count, getdns_transport_list_t *transports)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (getdns_set_base_dns_transports(context, transport_count, transports) != GETDNS_RETURN_GOOD)
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    /* Note that the call below does not have any effect in unbound after the
     * ctx is finalised so for recursive mode or stub + dnssec only the first
     * transport specified on the first query is used.
     * However the method returns success as otherwise the transport could not
     * be reset for stub mode.
     * Also, not all transport options supported in libunbound yet */
    if (set_ub_dns_transport(context) != GETDNS_RETURN_GOOD) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    dispatch_updated(context, GETDNS_CONTEXT_CODE_DNS_TRANSPORT);
    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_dns_transport_list */

/*
 * getdns_context_set_tls_authentication
 *
 */
getdns_return_t
getdns_context_set_tls_authentication(getdns_context *context,
                                      getdns_tls_authentication_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (value != GETDNS_AUTHENTICATION_NONE && 
        value != GETDNS_AUTHENTICATION_REQUIRED) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
    context->tls_auth = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_TLS_AUTHENTICATION);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_tls_authentication_list */

static void
set_ub_limit_outstanding_queries(struct getdns_context* context, uint16_t value) {
    /* num-queries-per-thread */
    set_ub_number_opt(context, "num-queries-per-thread:", value);
}
/*
 * getdns_context_set_limit_outstanding_queries
 *
 */
getdns_return_t
getdns_context_set_limit_outstanding_queries(struct getdns_context *context,
    uint16_t limit)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    set_ub_limit_outstanding_queries(context, limit);
    if (limit != context->limit_outstanding_queries) {
        context->limit_outstanding_queries = limit;
        dispatch_updated(context,
            GETDNS_CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES);
    }

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_limit_outstanding_queries */

/*
 * getdns_context_set_timeout
 *
 */
getdns_return_t
getdns_context_set_timeout(struct getdns_context *context, uint64_t timeout)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);

    if (timeout == 0) {
        return GETDNS_RETURN_INVALID_PARAMETER;
    }

    context->timeout = timeout;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_TIMEOUT);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_timeout */

/*
 * getdns_context_set_idle_timeout
 *
 */
getdns_return_t
getdns_context_set_idle_timeout(struct getdns_context *context, uint64_t timeout)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);

    /* Shuold we enforce maximum based on edns-tcp-keepalive spec? */
    /* 0 should be allowed as that is the default.*/

    context->idle_timeout = timeout;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_IDLE_TIMEOUT);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_timeout */


/*
 * getdns_context_set_follow_redirects
 *
 */
getdns_return_t
getdns_context_set_follow_redirects(
    getdns_context *context, getdns_redirects_t value)
{
	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (value != GETDNS_REDIRECTS_FOLLOW &&
	    value != GETDNS_REDIRECTS_DO_NOT_FOLLOW)
		return GETDNS_RETURN_INVALID_PARAMETER;

	context->follow_redirects = value;

	dispatch_updated(context, GETDNS_CONTEXT_CODE_FOLLOW_REDIRECTS);

	return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_follow_redirects */

/*
 * getdns_context_set_dns_root_servers
 *
 */
getdns_return_t
getdns_context_set_dns_root_servers(
    getdns_context *context, getdns_list *addresses)
{
#ifdef HAVE_LIBUNBOUND
#  ifndef HAVE_UB_CTX_SET_STUB
	char tmpfn[FILENAME_MAX] = P_tmpdir "/getdns-root-dns-servers-XXXXXX";
	FILE *fh;
	int fd;
	size_t dst_len;
#  endif
	size_t i;
	getdns_dict *rr_dict;
	getdns_return_t r = GETDNS_RETURN_GOOD;
	getdns_bindata *addr_bd;
	char dst[2048];
#endif
	getdns_list *newlist;

	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!addresses) {
#ifdef HAVE_LIBUNBOUND
		if (ub_ctx_set_option(
		    context->unbound_ctx, "root-hints:", ""))
			return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
#endif
		if (context->dns_root_servers)
			getdns_list_destroy(context->dns_root_servers);
		context->dns_root_servers = NULL;

#if defined(HAVE_LIBUNBOUND) && !defined(HAVE_UB_CTX_SET_STUB)
		if (context->root_servers_fn[0])
			unlink(context->root_servers_fn);
		context->root_servers_fn[0] = 0;
#endif
		dispatch_updated(
		    context, GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS);
		return GETDNS_RETURN_GOOD;
	}

#ifdef HAVE_LIBUNBOUND
#  ifdef HAVE_UB_CTX_SET_STUB
	for (i=0; !r; i++) {
		if (!(r = getdns_list_get_bindata(addresses, i, &addr_bd)))
			/* success! */
			;

		else if ((r = getdns_list_get_dict(addresses, i, &rr_dict)))
			/* Not a bindata, not a dict? ERROR! */
			break;

		else if (getdns_dict_get_bindata(
		    rr_dict, "address_data", &addr_bd) &&
		    getdns_dict_get_bindata(
		    rr_dict, "/rdata/ipv4_address", &addr_bd) &&
		    getdns_dict_get_bindata(
		    rr_dict, "/rdata/ipv6_address", &addr_bd))

		       	/* Not a parsable address,
			 * pass because we allow root.hint's files as input
			 */
			continue;

		if (addr_bd->size == 16 &&
		    inet_ntop(AF_INET6, addr_bd->data, dst, sizeof(dst))) {

			if (ub_ctx_set_stub(context->unbound_ctx,".",dst,1)) {
				return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
			}
		
		} else if (addr_bd->size == 4 &&
		    inet_ntop(AF_INET, addr_bd->data, dst, sizeof(dst))) {
			if (ub_ctx_set_stub(context->unbound_ctx,".",dst,1)) {
				return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
			}
		}
	}
#  else
	if ((fd = mkstemp(tmpfn)) < 0)
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;

	if (!(fh = fdopen(fd, "w")))
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	for (i=0; !r; i++) {
		dst_len = sizeof(dst);
		if (!(r = getdns_list_get_bindata(addresses, i, &addr_bd)))
			/* success! */
			;

		else if ((r = getdns_list_get_dict(addresses, i, &rr_dict)))
			/* Not a bindata, not a dict? ERROR! */
			break;

		else if (!getdns_rr_dict2str_buf(rr_dict, dst, &dst_len)) {

			fprintf(fh, "%s", dst);
			continue;

		} else if (getdns_dict_get_bindata(
		    rr_dict, "address_data", &addr_bd) &&
		    getdns_dict_get_bindata(
		    rr_dict, "/rdata/ipv4_address", &addr_bd) &&
		    getdns_dict_get_bindata(
		    rr_dict, "/rdata/ipv6_address", &addr_bd))

		       	/* Not a parsable address,
			 * pass because we allow root.hint's files as input
			 */
			continue;

		if (addr_bd->size == 16 &&
		    inet_ntop(AF_INET6, addr_bd->data, dst, sizeof(dst)))

			fprintf(fh,". NS "PRIsz".root-servers.getdnsapi.net.\n"
			    PRIsz".root-servers.getdnsapi.net. AAAA %s\n",
			    i, i, dst);

		else if (addr_bd->size == 4 &&
		    inet_ntop(AF_INET, addr_bd->data, dst, sizeof(dst)))

			fprintf(fh,". NS "PRIsz".root-servers.getdnsapi.net.\n"
			    PRIsz".root-servers.getdnsapi.net. A %s\n",
			    i, i, dst);
	}
	fclose(fh);
	if (ub_ctx_set_option(
	    context->unbound_ctx, "root-hints:", tmpfn)) {
		unlink(tmpfn);
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}
#  endif
#endif
	if (_getdns_list_copy(addresses, &newlist)) {
#if defined(HAVE_LIBUNBOUND) && !defined(HAVE_UB_CTX_SET_STUB)
		unlink(tmpfn);
#endif
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}
	if (context->dns_root_servers)
		getdns_list_destroy(context->dns_root_servers);
	context->dns_root_servers = newlist;

#if defined(HAVE_LIBUNBOUND) && !defined(HAVE_UB_CTX_SET_STUB)
	if (context->root_servers_fn[0])
		unlink(context->root_servers_fn);
	(void) memcpy(context->root_servers_fn, tmpfn, strlen(tmpfn));
#endif

	dispatch_updated(context, GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS);
	return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_dns_root_servers */

/*
 * getdns_context_set_append_name
 *
 */
getdns_return_t
getdns_context_set_append_name(
    getdns_context *context, getdns_append_name_t value)
{
	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;

	switch ((int)value) {
	case GETDNS_APPEND_NAME_ALWAYS:
	case GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE:
	case GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE:
	case GETDNS_APPEND_NAME_NEVER:
	case GETDNS_APPEND_NAME_TO_SINGLE_LABEL_FIRST:
		context->append_name = value;
		dispatch_updated(context, GETDNS_CONTEXT_CODE_APPEND_NAME);
		return GETDNS_RETURN_GOOD;
	}
	return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
}               /* getdns_context_set_append_name */

/*
 * getdns_context_set_suffix
 *
 */
getdns_return_t
getdns_context_set_suffix(getdns_context *context, getdns_list *value)
{
	getdns_return_t r;
	size_t i;
	gldns_buffer gbuf;
	uint8_t buf_spc[1024], *suffixes = NULL;
	size_t suffixes_len = 0;
	uint8_t dname[256];
	size_t dname_len;
	char name_spc[1025], *name;
	getdns_bindata *bindata;

	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (value == NULL) {
		if (context->suffixes && context->suffixes != no_suffixes)
			GETDNS_FREE(context->mf, (void *)context->suffixes);

		context->suffixes = no_suffixes;
		context->suffixes_len = sizeof(no_suffixes);
		return GETDNS_RETURN_GOOD;
	}
	gldns_buffer_init_frm_data(&gbuf, buf_spc, sizeof(buf_spc));
	for (;;) {
		for ( i = 0
		    ; !(r = getdns_list_get_bindata(value, i, &bindata))
		    ; i++) {

			if (bindata->size == 0 || bindata->size >= sizeof(name_spc))
				continue;

			if (bindata->data[bindata->size-1] != 0) {
				/* Unterminated string */
				(void) memcpy(name_spc, bindata->data, bindata->size);
				name_spc[bindata->size] = 0;
				name = name_spc;
			} else
				/* Terminated string */
				name = (char *)bindata->data;

			dname_len = sizeof(dname);
			if (gldns_str2wire_dname_buf(name, dname, &dname_len))
				return GETDNS_RETURN_GENERIC_ERROR;

			gldns_buffer_write_u8(&gbuf, dname_len);
			gldns_buffer_write(&gbuf, dname, dname_len);
		}
		if (r == GETDNS_RETURN_NO_SUCH_LIST_ITEM)
			r = GETDNS_RETURN_GOOD;
		else
			break;

		gldns_buffer_write_u8(&gbuf, 1);
		gldns_buffer_write_u8(&gbuf, 0);

		if (gldns_buffer_begin(&gbuf) != buf_spc)
			break;

		suffixes_len = gldns_buffer_position(&gbuf);
		if (!(suffixes = GETDNS_XMALLOC(
		    context->mf, uint8_t, suffixes_len))) {
			r = GETDNS_RETURN_MEMORY_ERROR;
			break;
		}
		if (suffixes_len <= gldns_buffer_limit(&gbuf)) {
			(void) memcpy (suffixes, buf_spc, suffixes_len);
			break;
		}
		gldns_buffer_init_frm_data(&gbuf, suffixes, suffixes_len);
	}
	if (r) {
		if (gldns_buffer_begin(&gbuf) != buf_spc)
			GETDNS_FREE(context->mf, suffixes);
		return r;
	}
	if (context->suffixes && context->suffixes != no_suffixes)
		GETDNS_FREE(context->mf, (void *)context->suffixes);

	context->suffixes = suffixes;
	context->suffixes_len = suffixes_len;

	dispatch_updated(context, GETDNS_CONTEXT_CODE_SUFFIX);
	return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_suffix */

/*
 * getdns_context_set_dnssec_trust_anchors
 *
 */
getdns_return_t
getdns_context_set_dnssec_trust_anchors(
    getdns_context *context, getdns_list *value)
{
	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);

	if (context->trust_anchors &&
	    context->trust_anchors != context->trust_anchors_spc)
		GETDNS_FREE(context->mf, context->trust_anchors);

	if (value) {
		context->trust_anchors_len = sizeof(context->trust_anchors_spc);
		context->trust_anchors = _getdns_list2wire(value,
		    context->trust_anchors_spc, &context->trust_anchors_len,
		    &context->mf);
	} else {
		context->trust_anchors = NULL;
		context->trust_anchors_len = 0;
	}
	dispatch_updated(context, GETDNS_CONTEXT_CODE_DNSSEC_TRUST_ANCHORS);
	return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_dnssec_trust_anchors */

static void
set_ub_dnssec_allowed_skew(struct getdns_context* context, uint32_t value) {
    set_ub_number_opt(context, "val-sig-skew-min:", value);
    set_ub_number_opt(context, "val-sig-skew-max:", value);
}
/*
 * getdns_context_set_dnssec_allowed_skew
 *
 */
getdns_return_t
getdns_context_set_dnssec_allowed_skew(struct getdns_context *context,
    uint32_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    set_ub_dnssec_allowed_skew(context, value);
    if (value != context->dnssec_allowed_skew) {
        context->dnssec_allowed_skew = value;
        dispatch_updated(context, GETDNS_CONTEXT_CODE_DNSSEC_ALLOWED_SKEW);
    }

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_dnssec_allowed_skew */

/*
 * getdns_context_set_upstream_recursive_servers
 *
 */
getdns_return_t
getdns_context_set_upstream_recursive_servers(struct getdns_context *context,
    struct getdns_list *upstream_list)
{
	getdns_return_t r;
	size_t count = 0;
	size_t i;
	getdns_upstreams *upstreams;
	char addrstr[1024], portstr[1024], *eos;
	struct addrinfo hints;

	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
	RETURN_IF_NULL(upstream_list, GETDNS_RETURN_INVALID_PARAMETER);

	r = getdns_list_get_length(upstream_list, &count);
	if (count == 0 || r != GETDNS_RETURN_GOOD) {
		return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
	}
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
	hints.ai_socktype  = 0;              /* Datagram socket */
	hints.ai_flags     = AI_NUMERICHOST; /* No reverse name lookups */
	hints.ai_protocol  = 0;              /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr      = NULL;
	hints.ai_next      = NULL;

	upstreams = upstreams_create(
	    context, count * GETDNS_UPSTREAM_TRANSPORTS);
	for (i = 0; i < count; i++) {
		getdns_dict    *dict;
		getdns_bindata *address_type;
		getdns_bindata *address_data;
		getdns_bindata *tls_auth_name;
		struct sockaddr_storage  addr;

		getdns_bindata  *scope_id;
		getdns_upstream *upstream;

		getdns_bindata  *tsig_alg_name, *tsig_name, *tsig_key;
		getdns_tsig_algo tsig_alg;
		char             tsig_name_str[1024];
		uint8_t          tsig_dname_spc[256], *tsig_dname;
		size_t           tsig_dname_len;

		if ((r = getdns_list_get_dict(upstream_list, i, &dict))) {
			dict = NULL;

			if ((r = getdns_list_get_bindata(
			    upstream_list, i, &address_data)))
				goto error;

			if (address_data->size == 4)
				addr.ss_family = AF_INET;
			else if (address_data->size == 16)
				addr.ss_family = AF_INET6;
			else	goto invalid_parameter;

		} else if ((r = getdns_dict_get_bindata(
		    dict, "address_type",&address_type))) {
			/* Just address_data is also okay */
			if ((r = getdns_dict_get_bindata(
			    dict, "address_data", &address_data)))
				goto error;

			if (address_data->size == 4)
				addr.ss_family = AF_INET;
			else if (address_data->size == 16)
				addr.ss_family = AF_INET6;
			else	goto invalid_parameter;

		} else {
			if (address_type->size < 4)
				goto invalid_parameter;
			else if (!strncmp((char*)address_type->data,"IPv4",4))
				addr.ss_family = AF_INET;
			else if (!strncmp((char*)address_type->data,"IPv6",4))
				addr.ss_family = AF_INET6;
			else	goto invalid_parameter;

			if ((r = getdns_dict_get_bindata(
			    dict, "address_data", &address_data)))
				goto error;
			if ((addr.ss_family == AF_INET &&
			     address_data->size != 4) ||
			    (addr.ss_family == AF_INET6 &&
			     address_data->size != 16))
				goto invalid_parameter;
		}
		if (inet_ntop(addr.ss_family, address_data->data,
		    addrstr, 1024) == NULL)
			goto invalid_parameter;

		if (dict && getdns_dict_get_bindata(dict,"scope_id",&scope_id)
		    == GETDNS_RETURN_GOOD) {
			if (strlen(addrstr) + scope_id->size > 1022)
				goto invalid_parameter;
			eos = &addrstr[strlen(addrstr)];
			*eos++ = '%';
			(void) memcpy(eos, scope_id->data, scope_id->size);
			eos[scope_id->size] = 0;
		}

		tsig_alg_name = tsig_name = tsig_key = NULL;
		tsig_dname = NULL;
		tsig_dname_len = 0;

		if (dict && getdns_dict_get_bindata(dict,
		    "tsig_algorithm", &tsig_alg_name) == GETDNS_RETURN_GOOD)
			tsig_alg = _getdns_get_tsig_algo(tsig_alg_name);
		else
			tsig_alg = GETDNS_HMAC_MD5;

		if (!dict)
			tsig_alg = GETDNS_NO_TSIG; /* No name, no TSIG */

		else if (getdns_dict_get_bindata(
		    dict, "tsig_name", &tsig_name))
			tsig_alg = GETDNS_NO_TSIG; /* No name, no TSIG */

		else if (tsig_name->size == 0)
			tsig_alg = GETDNS_NO_TSIG;

		else if (tsig_name->data[tsig_name->size - 1] != 0) {
			/* Unterminated string */
			if (tsig_name->size >= sizeof(tsig_name_str) - 1)
				tsig_alg = GETDNS_NO_TSIG;
			else {
				(void) memcpy(tsig_name_str, tsig_name->data
				                           , tsig_name->size);
				tsig_name_str[tsig_name->size] = 0;

				tsig_dname_len = sizeof(tsig_dname_spc);
				if (gldns_str2wire_dname_buf(tsig_name_str,
				    tsig_dname_spc, &tsig_dname_len))
					tsig_alg = GETDNS_NO_TSIG;
				else
					tsig_dname = tsig_dname_spc;
			}
		} else if (!_getdns_bindata_is_dname(tsig_name)) {
			/* Terminated string */
			tsig_dname_len = sizeof(tsig_dname_spc);
			if (gldns_str2wire_dname_buf(tsig_name_str,
			    tsig_dname_spc, &tsig_dname_len))
				tsig_alg = GETDNS_NO_TSIG;
			else
				tsig_dname = tsig_dname_spc;

		} else if (tsig_name->size > sizeof(tsig_dname_spc))
			tsig_alg = GETDNS_NO_TSIG;

		else {
			/* fqdn */
			tsig_dname = memcpy(tsig_dname_spc, tsig_name->data
			                                  , tsig_name->size);
			tsig_dname_len = tsig_name->size;
		}
		if (dict && getdns_dict_get_bindata(
		    dict, "tsig_secret", &tsig_key))
			tsig_alg = GETDNS_NO_TSIG; /* No key, no TSIG */

		/* Don't check TSIG length contraints here.
		 * Let the upstream decide what is secure enough.
		 */

		/* Loop to create upstreams as needed*/
		for (size_t j = 0; j < GETDNS_UPSTREAM_TRANSPORTS; j++) {
			uint32_t port;
			struct addrinfo *ai;
			port = getdns_port_array[j];
			if (port == GETDNS_PORT_ZERO)
				continue;

			if (getdns_upstream_transports[j] != GETDNS_TRANSPORT_TLS) {
				if (dict)
					(void) getdns_dict_get_int(dict, "port", &port);
			} else {
				if (dict)
					(void) getdns_dict_get_int(dict, "tls_port", &port);
			}
			(void) snprintf(portstr, 1024, "%d", (int)port);

			if (getaddrinfo(addrstr, portstr, &hints, &ai))
				goto invalid_parameter;
			if (!ai)
				continue;

			/* TODO[TLS]: Should probably check that the upstream doesn't
			 * already exist (in case user has specified TLS port explicitly and
			 * to prevent duplicates) */

			upstream = &upstreams->upstreams[upstreams->count];
			upstream->addr.ss_family = addr.ss_family;
			upstream_init(upstream, upstreams, ai);
			upstream->transport = getdns_upstream_transports[j];
			if (getdns_upstream_transports[j] == GETDNS_TRANSPORT_TLS) {
				getdns_list *pubkey_pinset = NULL;
				if (dict && (r = getdns_dict_get_bindata(
					dict, "tls_auth_name", &tls_auth_name)) == GETDNS_RETURN_GOOD) {
					/*TODO: VALIDATE THIS STRING!*/
					memcpy(upstream->tls_auth_name,
					       (char *)tls_auth_name->data,
						tls_auth_name->size);
					upstream->tls_auth_name[tls_auth_name->size] = '\0';
				}
				if (dict && (r = getdns_dict_get_list(dict, "tls_pubkey_pinset",
							      &pubkey_pinset)) == GETDNS_RETURN_GOOD) {
			   /* TODO: what if the user supplies tls_pubkey_pinset with
			    * something other than a list? */
					r = _getdns_get_pubkey_pinset_from_list(pubkey_pinset,
										&(upstreams->mf),
										&(upstream->tls_pubkey_pinset));
					if (r != GETDNS_RETURN_GOOD)
						goto invalid_parameter;
				}
			}
			if ((upstream->tsig_alg = tsig_alg)) {
				if (tsig_name) {
					(void) memcpy(upstream->tsig_dname,
					    tsig_dname, tsig_dname_len);
					upstream->tsig_dname_len =
						tsig_dname_len;
				} else
					upstream->tsig_dname_len = 0;

				if (tsig_key) {
					(void) memcpy(upstream->tsig_key,
					    tsig_key->data, tsig_key->size);
					upstream->tsig_size = tsig_key->size;
				} else
					upstream->tsig_size = 0;
			} else {
				upstream->tsig_dname_len = 0;
				upstream->tsig_size = 0;
			}
			upstreams->count++;
			freeaddrinfo(ai);
		}
	}
	_getdns_upstreams_dereference(context->upstreams);
	context->upstreams = upstreams;
	dispatch_updated(context,
		GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS);

	return GETDNS_RETURN_GOOD;

invalid_parameter:
	_getdns_upstreams_dereference(upstreams);
	return GETDNS_RETURN_INVALID_PARAMETER;
error:
	_getdns_upstreams_dereference(upstreams);
	return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
} /* getdns_context_set_upstream_recursive_servers */


static void
set_ub_edns_maximum_udp_payload_size(struct getdns_context* context,
    int value) {
    /* edns-buffer-size */
    if (value >= 512 && value <= 65535)
    	set_ub_number_opt(context, "edns-buffer-size:", (uint16_t)value);
}

/*
 * getdns_context_set_edns_maximum_udp_payload_size
 *
 */
getdns_return_t
getdns_context_set_edns_maximum_udp_payload_size(struct getdns_context *context,
    uint16_t value)
{
	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;

	/* check for < 512.  uint16_t won't let it go above max) */
	if (value < 512)
		value = 512;

	set_ub_edns_maximum_udp_payload_size(context, value);
	if (value != context->edns_maximum_udp_payload_size) {
		context->edns_maximum_udp_payload_size = value;
		dispatch_updated(context,
		    GETDNS_CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE);
	}
	return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_edns_maximum_udp_payload_size */

/*
 * getdns_context_set_edns_extended_rcode
 *
 */
getdns_return_t
getdns_context_set_edns_extended_rcode(struct getdns_context *context, uint8_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    context->edns_extended_rcode = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_EXTENDED_RCODE);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_edns_extended_rcode */

/*
 * getdns_context_set_edns_version
 *
 */
getdns_return_t
getdns_context_set_edns_version(struct getdns_context *context, uint8_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    context->edns_version = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_VERSION);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_edns_version */

/*
 * getdns_context_set_edns_do_bit
 *
 */
getdns_return_t
getdns_context_set_edns_do_bit(struct getdns_context *context, uint8_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    /* only allow 1 */
    if (value != 0 && value != 1) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }

    context->edns_do_bit = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_DO_BIT);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_edns_do_bit */

/*
 * getdns_context_set_edns_client_subnet_private
 *
 */
getdns_return_t
getdns_context_set_edns_client_subnet_private(struct getdns_context *context, uint8_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    /* only allow 1 */
    if (value != 0 && value != 1) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }

    context->edns_client_subnet_private = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_EDNS_CLIENT_SUBNET_PRIVATE);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_edns_client_subnet_private */

/*
 * getdns_context_set_tls_query_padding_blocksize
 *
 */
getdns_return_t
getdns_context_set_tls_query_padding_blocksize(struct getdns_context *context, uint16_t value)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    /* only allow values between 0 and MAXIMUM_UPSTREAM_OPTION_SPACE - 4
       (4 is for the overhead of the option itself) */
    if (value > MAXIMUM_UPSTREAM_OPTION_SPACE - 4) {
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }

    context->tls_query_padding_blocksize = value;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_TLS_QUERY_PADDING_BLOCKSIZE);

    return GETDNS_RETURN_GOOD;
}               /* getdns_context_set_tls_query_padding_blocksize */
/*
 * getdns_context_set_extended_memory_functions
 *
 */
getdns_return_t
getdns_context_set_extended_memory_functions(
    struct getdns_context *context,
    void *userarg,
    void *(*malloc) (void *userarg, size_t),
    void *(*realloc) (void *userarg, void *, size_t),
    void (*free) (void *userarg, void *)
    )
{
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (!malloc || !realloc || !free)
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;

    context->mf.mf_arg         = userarg;
    context->mf.mf.ext.malloc  = malloc;
    context->mf.mf.ext.realloc = realloc;
    context->mf.mf.ext.free    = free;

    dispatch_updated(context, GETDNS_CONTEXT_CODE_MEMORY_FUNCTIONS);

    return GETDNS_RETURN_GOOD;
} /* getdns_context_set_extended_memory_functions*/


/*
 * getdns_context_set_memory_functions
 *
 */
getdns_return_t
getdns_context_set_memory_functions(struct getdns_context *context,
    void *(*malloc) (size_t),
    void *(*realloc) (void *, size_t),
    void (*free) (void *)
    )
{
    mf_union mf;
    mf.pln.malloc = malloc;
    mf.pln.realloc = realloc;
    mf.pln.free = free;
    return getdns_context_set_extended_memory_functions(
        context, MF_PLAIN, mf.ext.malloc, mf.ext.realloc, mf.ext.free);
} /* getdns_context_set_memory_functions*/

/* cancel the request */
static void
cancel_dns_req(getdns_dns_req *req)
{
	getdns_network_req *netreq, **netreq_p;

	for (netreq_p = req->netreqs; (netreq = *netreq_p); netreq_p++)
#ifdef HAVE_LIBUNBOUND
		if (netreq->unbound_id != -1) {
			ub_cancel(req->context->unbound_ctx,
			    netreq->unbound_id);
			netreq->unbound_id = -1;
		} else
#endif
			_getdns_cancel_stub_request(netreq);

	req->canceled = 1;
}

getdns_return_t
_getdns_context_cancel_request(getdns_context *context,
    getdns_transaction_t transaction_id, int fire_callback)
{
	getdns_dns_req *dnsreq;

	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;

	/* delete the node from the tree */
	if (!(dnsreq = (getdns_dns_req *)_getdns_rbtree_delete(
	    &context->outbound_requests, &transaction_id)))
		return GETDNS_RETURN_UNKNOWN_TRANSACTION;

	/* do the cancel */
	cancel_dns_req(dnsreq);

	if (fire_callback) {
		context->processing = 1;
		dnsreq->user_callback(context, GETDNS_CALLBACK_CANCEL,
		    NULL, dnsreq->user_pointer, transaction_id);
		context->processing = 0;
	}

	/* clean up */
	_getdns_dns_req_free(dnsreq);
	return GETDNS_RETURN_GOOD;
}

/*
 * getdns_cancel_callback
 *
 */
getdns_return_t
getdns_cancel_callback(getdns_context *context,
    getdns_transaction_t transaction_id)
{
	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;

	getdns_return_t r = _getdns_context_cancel_request(context, transaction_id, 1);
	getdns_context_request_count_changed(context);
	return r;
} /* getdns_cancel_callback */

#ifndef STUB_NATIVE_DNSSEC
static uint8_t*
upstream_addr(getdns_upstream *upstream)
{
	return upstream->addr.ss_family == AF_INET
	    ? (void *)&((struct sockaddr_in*)&upstream->addr)->sin_addr
	    : (void *)&((struct sockaddr_in6*)&upstream->addr)->sin6_addr;
}

static in_port_t
upstream_port(getdns_upstream *upstream)
{
	return ntohs(upstream->addr.ss_family == AF_INET
	    ? ((struct sockaddr_in *)&upstream->addr)->sin_port
	    : ((struct sockaddr_in6*)&upstream->addr)->sin6_port);
}

static uint32_t *
upstream_scope_id(getdns_upstream *upstream)
{
	return upstream->addr.ss_family == AF_INET ? NULL
	    : (upstream_addr(upstream)[0] == 0xFE &&
	       (upstream_addr(upstream)[1] & 0xC0) == 0x80 ?
	       &((struct sockaddr_in6*)&upstream->addr)->sin6_scope_id : NULL);
}

static void
upstream_ntop_buf(getdns_upstream *upstream, char *buf, size_t len)
{
	/* Also possible but prints scope_id by name (nor parsed by unbound)
	 *
	 * getnameinfo((struct sockaddr *)&upstream->addr, upstream->addr_len,
	 *     buf, len, NULL, 0, NI_NUMERICHOST)
	 */
	(void) inet_ntop(upstream->addr.ss_family, upstream_addr(upstream),
	    buf, len);
	if (upstream_scope_id(upstream))
		(void) snprintf(buf + strlen(buf), len - strlen(buf),
		    "%%%d", (int)*upstream_scope_id(upstream));
	else if (upstream_port(upstream) != GETDNS_PORT_DNS && upstream_port(upstream) != GETDNS_PORT_ZERO)
		(void) snprintf(buf + strlen(buf), len - strlen(buf),
		    "@%d", (int)upstream_port(upstream));
}

static getdns_return_t
ub_setup_stub(struct ub_ctx *ctx, getdns_context *context)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	size_t i;
	getdns_upstream *upstream;
	char addr[1024];
	getdns_upstreams *upstreams = context->upstreams;

	(void) ub_ctx_set_fwd(ctx, NULL);
	for (i = 0; i < upstreams->count; i++) {
		upstream = &upstreams->upstreams[i];
		/*[TLS]: Use only the TLS subset of upstreams when TLS is the only thing
		 * used. All other cases must currently fallback to TCP for libunbound.*/
		if (context->dns_transports[0] == GETDNS_TRANSPORT_TLS &&
		    context->dns_transport_count ==1 &&
			upstream->transport !=  GETDNS_TRANSPORT_TLS)
				continue;
		upstream_ntop_buf(upstream, addr, 1024);
		ub_ctx_set_fwd(ctx, addr);
	}

	/* Allow lookups of:
	 */
	/* - localhost */
	(void)ub_ctx_zone_remove(ctx, "localhost.");

	/* - reverse IPv4 loopback */
	(void)ub_ctx_zone_remove(ctx, "127.in-addr.arpa.");

	/* - reverse IPv6 loopback */
	(void)ub_ctx_zone_remove(ctx, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
	                              "0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.");

	/* - reverse RFC1918 local use zones */
	(void)ub_ctx_zone_remove(ctx, "10.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "16.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "17.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "18.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "19.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "20.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "21.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "22.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "23.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "24.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "25.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "26.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "27.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "28.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "29.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "30.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "31.172.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "168.192.in-addr.arpa.");

	/* - reverse RFC3330 IP4 this, link-local, testnet and broadcast */
	(void)ub_ctx_zone_remove(ctx, "0.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "254.169.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "2.0.192.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "100.51.198.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "113.0.203.in-addr.arpa.");
	(void)ub_ctx_zone_remove(ctx, "255.255.255.255.in-addr.arpa.");

	/* - reverse RFC4291 IP6 unspecified */
	(void)ub_ctx_zone_remove(ctx, "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
	                              "0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.");

	/* - reverse RFC4193 IPv6 Locally Assigned Local Addresses */
	(void)ub_ctx_zone_remove(ctx, "D.F.ip6.arpa.");

	/* - reverse RFC4291 IPv6 Link Local Addresses */
	(void)ub_ctx_zone_remove(ctx, "8.E.F.ip6.arpa.");
	(void)ub_ctx_zone_remove(ctx, "9.E.F.ip6.arpa.");
	(void)ub_ctx_zone_remove(ctx, "A.E.F.ip6.arpa.");
	(void)ub_ctx_zone_remove(ctx, "B.E.F.ip6.arpa.");

	/* - reverse IPv6 Example Prefix */
	(void)ub_ctx_zone_remove(ctx, "8.B.D.0.1.0.0.2.ip6.arpa.");

	return r;
}
#endif


#ifdef HAVE_LIBUNBOUND
static getdns_return_t
ub_setup_recursing(struct ub_ctx *ctx, getdns_context *context)
{
	_getdns_rr_iter rr_spc, *rr;
	char ta_str[8192];

	(void) ub_ctx_set_fwd(ctx, NULL);
	if (!context->unbound_ta_set && context->trust_anchors) {
		for ( rr = _getdns_rr_iter_init( &rr_spc
		                               , context->trust_anchors
		                               , context->trust_anchors_len)
		    ; rr ; rr = _getdns_rr_iter_next(rr) ) {

			(void) gldns_wire2str_rr_buf((UNCONST_UINT8_p)rr->pos,
			    rr->nxt - rr->pos, ta_str, sizeof(ta_str));
			(void) ub_ctx_add_ta(ctx, ta_str);
		}
		context->unbound_ta_set = 1;
	}
	return GETDNS_RETURN_GOOD;
}
#endif

static getdns_return_t
_getdns_ns_dns_setup(struct getdns_context *context)
{
	assert(context);

	switch (context->resolution_type) {
	case GETDNS_RESOLUTION_STUB:
		if (!context->upstreams || !context->upstreams->count)
			return GETDNS_RETURN_GENERIC_ERROR;
#ifdef STUB_NATIVE_DNSSEC
# ifdef DNSSEC_ROADBLOCK_AVOIDANCE
#  ifdef HAVE_LIBUNBOUND
		return ub_setup_recursing(context->unbound_ctx, context);
#  else
		/* Return NOT_IMPLEMENTED on query with an
		 * roadblock avoidance extension.
		 */
		return GETDNS_RETURN_GOOD;
#  endif
# else
		return GETDNS_RETURN_GOOD;
# endif
#else
		return ub_setup_stub(context->unbound_ctx, context);
#endif

	case GETDNS_RESOLUTION_RECURSING:
#ifdef HAVE_LIBUNBOUND
		return ub_setup_recursing(context->unbound_ctx, context);
#else
		return GETDNS_RETURN_NOT_IMPLEMENTED;
#endif
	}
	return GETDNS_RETURN_BAD_CONTEXT;
}

getdns_return_t
_getdns_context_prepare_for_resolution(struct getdns_context *context,
    int usenamespaces)
{
	int i;
	getdns_return_t r;

	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (context->destroying) {
        return GETDNS_RETURN_BAD_CONTEXT;
    }

	/* Transport can in theory be set per query in stub mode */
	if (context->resolution_type == GETDNS_RESOLUTION_STUB && 
	    tls_is_in_transports_list(context) == 1) {
		/* Check minimum require authentication level*/
		if (tls_only_is_in_transports_list(context) == 1 && 
		    context->tls_auth == GETDNS_AUTHENTICATION_REQUIRED) {
			context->tls_auth_min = GETDNS_AUTHENTICATION_REQUIRED;
			/* TODO: If no auth data provided for any upstream, fail here */
		}
		else {
			context->tls_auth_min = GETDNS_AUTHENTICATION_NONE;
		}

		if (context->tls_ctx == NULL) {
#ifdef HAVE_TLS_v1_2
			/* Create client context, use TLS v1.2 only for now */
#  ifdef HAVE_TLS_CLIENT_METHOD
			context->tls_ctx = SSL_CTX_new(TLS_client_method());
#  else
			context->tls_ctx = SSL_CTX_new(TLSv1_2_client_method());
#  endif
			if(context->tls_ctx == NULL)
				return GETDNS_RETURN_BAD_CONTEXT;

#  ifdef HAVE_TLS_CLIENT_METHOD
			if (!SSL_CTX_set_min_proto_version(
			    context->tls_ctx, TLS1_2_VERSION)) {
				SSL_CTX_free(context->tls_ctx);
				context->tls_ctx = NULL;
				return GETDNS_RETURN_BAD_CONTEXT;
			}
#  endif
			/* Be strict and only use the cipher suites recommended in RFC7525
			   Unless we later fallback to opportunistic. */
			const char* const PREFERRED_CIPHERS = "EECDH+aRSA+AESGCM:EECDH+aECDSA+AESGCM:EDH+aRSA+AESGCM";
			if (!SSL_CTX_set_cipher_list(context->tls_ctx, PREFERRED_CIPHERS))
				return GETDNS_RETURN_BAD_CONTEXT;
			/* For strict authentication, we must have local root certs available
		       Set up is done only when the tls_ctx is created (per getdns_context)*/
#  ifndef USE_WINSOCK
			if (!SSL_CTX_set_default_verify_paths(context->tls_ctx)) {
#  else
			if (!add_WIN_cacerts_to_openssl_store(context->tls_ctx)) {
#  endif /* USE_WINSOCK */
				if (context->tls_auth_min == GETDNS_AUTHENTICATION_REQUIRED) 
					return GETDNS_RETURN_BAD_CONTEXT;
			}
#else /* HAVE_TLS_v1_2 */
			if (tls_only_is_in_transports_list(context) == 1)
				return GETDNS_RETURN_BAD_CONTEXT;
			/* A null tls_ctx will make TLS fail and fallback to the other
			   transports will kick-in.*/
#endif /* HAVE_TLS_v1_2 */
		}
	}

	/* Block use of TLS ONLY in recursive mode as it won't work */
    /* Note: If TLS is used in recursive mode this will try TLS on port
     * 53 so it is blocked here. */
	if (context->resolution_type == GETDNS_RESOLUTION_RECURSING &&
		tls_only_is_in_transports_list(context) == 1)
		return GETDNS_RETURN_BAD_CONTEXT;

	if (context->resolution_type_set == context->resolution_type)
        	/* already set and no config changes
		 * have caused this to be bad.
		 */
		return GETDNS_RETURN_GOOD;

	/* TODO: respect namespace order (unbound always uses local first if cfg
	 * the spec calls for us to treat the namespace list as ordered
	 * so we need to respect that order
	 */


	if (! usenamespaces) {
		r = _getdns_ns_dns_setup(context);
		if (r == GETDNS_RETURN_GOOD)
			context->resolution_type_set = context->resolution_type;
		return r;
	}

	r = GETDNS_RETURN_GOOD;
	for (i = 0; i < context->namespace_count; i++) {
		switch (context->namespaces[i]) {
		case GETDNS_NAMESPACE_DNS:
			r = _getdns_ns_dns_setup(context);
			break;

		default:
			r = GETDNS_RETURN_BAD_CONTEXT;
			break;
		}
		if (r != GETDNS_RETURN_GOOD)
			return r; /* try again later (resolution_type_set) */
	}
	context->resolution_type_set = context->resolution_type;
	return r;
} /* _getdns_context_prepare_for_resolution */

getdns_return_t
_getdns_context_track_outbound_request(getdns_dns_req *dnsreq)
{
    	if (!dnsreq)
		return GETDNS_RETURN_INVALID_PARAMETER;

	dnsreq->node.key = &(dnsreq->trans_id);
	if (!_getdns_rbtree_insert(
	    &dnsreq->context->outbound_requests, &dnsreq->node))
		return GETDNS_RETURN_GENERIC_ERROR;

	getdns_context_request_count_changed(dnsreq->context);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_context_clear_outbound_request(getdns_dns_req *dnsreq)
{
    	if (!dnsreq)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!_getdns_rbtree_delete(
	    &dnsreq->context->outbound_requests, &dnsreq->trans_id))
		return GETDNS_RETURN_GENERIC_ERROR;

	getdns_context_request_count_changed(dnsreq->context);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_context_request_timed_out(getdns_dns_req *req)
{
	/* Don't use req after callback */
	getdns_context* context = req->context;
	getdns_transaction_t trans_id = req->trans_id;
	getdns_callback_t cb = req->user_callback;
	void *user_arg = req->user_pointer;
	getdns_dict *response = _getdns_create_getdns_response(req);

	/* cancel the req - also clears it from outbound and cleans up*/
	_getdns_context_cancel_request(context, trans_id, 0);
	context->processing = 1;
	cb(context, GETDNS_CALLBACK_TIMEOUT, response, user_arg, trans_id);
	context->processing = 0;
	getdns_context_request_count_changed(context);
	return GETDNS_RETURN_GOOD;
}

char *
_getdns_strdup(const struct mem_funcs *mfs, const char *s)
{
    size_t sz = strlen(s) + 1;
    char *r = GETDNS_XMALLOC(*mfs, char, sz);
    if (r)
        return memcpy(r, s, sz);
    else
        return NULL;
}

struct getdns_bindata *
_getdns_bindata_copy(struct mem_funcs *mfs, size_t size, const uint8_t *data)
{
	/* Don't know why, but nodata allows
	 * empty bindatas with the python bindings
	 */
	static uint8_t nodata[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	struct getdns_bindata *dst;

	if (!(dst = GETDNS_MALLOC(*mfs, struct getdns_bindata)))
		return NULL;

	if ((dst->size = size)) {
		dst->data = GETDNS_XMALLOC(*mfs, uint8_t, size);
		if (!dst->data) {
			GETDNS_FREE(*mfs, dst);
			return NULL;
		}
		(void) memcpy(dst->data, data, size);
	} else {
		dst->data = nodata;
	}
	return dst;
}

void
_getdns_bindata_destroy(struct mem_funcs *mfs,
    struct getdns_bindata *bindata)
{
	if (!bindata)
		return;

	if (bindata->size) GETDNS_FREE(*mfs, bindata->data);
	GETDNS_FREE(*mfs, bindata);
}

/* TODO: Remove next_timeout argument from getdns_context_get_num_pending_requests
 */
uint32_t
getdns_context_get_num_pending_requests(getdns_context* context,
    struct timeval* next_timeout)
{
	(void)next_timeout;

	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (context->outbound_requests.count)
		context->extension->vmt->run_once(context->extension, 0);

	return context->outbound_requests.count;
}

/* process async reqs */
getdns_return_t
getdns_context_process_async(getdns_context *context)
{
	if (!context)
		return GETDNS_RETURN_INVALID_PARAMETER;

	context->extension->vmt->run_once(context->extension, 0);
	return GETDNS_RETURN_GOOD;
}

void
getdns_context_run(getdns_context *context)
{
	context->extension->vmt->run(context->extension);
}

typedef struct timeout_accumulator {
    getdns_transaction_t* ids;
    int idx;
} timeout_accumulator;

static void
accumulate_outstanding_transactions(_getdns_rbnode_t* node, void* arg) {
    timeout_accumulator* acc = (timeout_accumulator*) arg;
    acc->ids[acc->idx] = *((getdns_transaction_t*) node->key);
    acc->idx++;
}

static void
cancel_outstanding_requests(struct getdns_context* context, int fire_callback) {
    if (context->outbound_requests.count > 0) {
        timeout_accumulator acc;
        int i;
        acc.idx = 0;
        acc.ids = GETDNS_XMALLOC(context->my_mf, getdns_transaction_t, context->outbound_requests.count);
        _getdns_traverse_postorder(&context->outbound_requests, accumulate_outstanding_transactions, &acc);
        for (i = 0; i < acc.idx; ++i) {
            _getdns_context_cancel_request(context, acc.ids[i], fire_callback);
        }
        GETDNS_FREE(context->my_mf, acc.ids);
    }
}

getdns_return_t
getdns_context_detach_eventloop(struct getdns_context* context)
{
	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);

	/* When called from within a callback, do not execute pending
	 * context destroys.
	 * The (other) callback handler will handle it.
	 *
	 * ( because callbacks occur in cancel_outstanding_requests,
	 *   and they may destroy the context )
	 */
	/* cancel all outstanding requests */
	cancel_outstanding_requests(context, 1);
	context->extension->vmt->cleanup(context->extension);
	context->extension = &context->default_eventloop.loop;
	_getdns_default_eventloop_init(&context->default_eventloop);
#ifdef HAVE_UNBOUND_EVENT_API
	if (_getdns_ub_loop_enabled(&context->ub_loop))
		context->ub_loop.extension = context->extension;
#endif
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_set_eventloop(getdns_context* context, getdns_eventloop* loop)
{
	if (!context || !loop)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (context->extension) {
		cancel_outstanding_requests(context, 1);
		context->extension->vmt->cleanup(context->extension);
	}
	context->extension = loop;
#ifdef HAVE_UNBOUND_EVENT_API
	if (_getdns_ub_loop_enabled(&context->ub_loop))
		context->ub_loop.extension = loop;
#endif
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_eventloop(getdns_context *context, getdns_eventloop **loop)
{
	if (!context || !loop)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!context->extension)
		return GETDNS_RETURN_GENERIC_ERROR;
	else
		*loop = context->extension;

	return GETDNS_RETURN_GOOD;
}

static in_port_t
upstream_port(getdns_upstream *upstream)
{
	return ntohs(upstream->addr.ss_family == AF_INET
	     ? ((struct sockaddr_in *)&upstream->addr)->sin_port
	     : ((struct sockaddr_in6*)&upstream->addr)->sin6_port);
}

static getdns_dict*
_get_context_settings(getdns_context* context)
{
	getdns_dict *result = getdns_dict_create_with_context(context);
	getdns_list *list;
	size_t       i;

	if (!result)
		return NULL;

	/* int fields */
	if (   getdns_dict_set_int(result, "timeout",
	                           context->timeout)
	    || getdns_dict_set_int(result, "idle_timeout",
	                           context->idle_timeout)
	    || getdns_dict_set_int(result, "limit_outstanding_queries",
	                           context->limit_outstanding_queries)
            || getdns_dict_set_int(result, "dnssec_allowed_skew",
	                           context->dnssec_allowed_skew)
	    || getdns_dict_set_int(result, "follow_redirects",
	                           context->follow_redirects)
	    || (  context->edns_maximum_udp_payload_size != -1
	       && getdns_dict_set_int(result, "edns_maximum_udp_payload_size",
	                              context->edns_maximum_udp_payload_size))
	    || getdns_dict_set_int(result, "edns_extended_rcode",
	                           context->edns_extended_rcode)
	    || getdns_dict_set_int(result, "edns_version",
	                           context->edns_version)
	    || getdns_dict_set_int(result, "edns_do_bit",
	                           context->edns_do_bit)
	    || getdns_dict_set_int(result, "append_name",
	                           context->append_name)
	    || getdns_dict_set_int(result, "tls_authentication",
	                           context->tls_auth))
		goto error;
	
	/* list fields */
	if (getdns_context_get_suffix(context, &list))
		goto error;

	if (_getdns_dict_set_this_list(result, "suffix", list)) {
		getdns_list_destroy(list);
		goto error;
	}
	if (getdns_context_get_upstream_recursive_servers(context, &list))
		goto error;

	if (_getdns_dict_set_this_list(
	    result, "upstream_recursive_servers", list)) {
		getdns_list_destroy(list);
		goto error;
	}
	if (context->dns_transport_count > 0) {
		/* create a namespace list */
		if (!(list = getdns_list_create_with_context(context)))
			goto error;

		for (i = 0; i < context->dns_transport_count; ++i) {
			if (getdns_list_set_int(list, i,
			    context->dns_transports[i])) {
				getdns_list_destroy(list);
				goto error;
			}
		}
		if (_getdns_dict_set_this_list(
		    result, "dns_transport_list", list)) {
			getdns_list_destroy(list);
			goto error;
		}
	}
	if (context->namespace_count > 0) {
        /* create a namespace list */
		if (!(list = getdns_list_create_with_context(context)))
			goto error;

		for (i = 0; i < context->namespace_count; ++i) {
			if (getdns_list_set_int(list, i,
			    context->namespaces[i])) {
				getdns_list_destroy(list);
				goto error;
			}
		}
		if (_getdns_dict_set_this_list(result, "namespaces", list)) {
			getdns_list_destroy(list);
			return NULL;
		}
	}
	return result;
error:
	getdns_dict_destroy(result);
	return NULL;
}

getdns_dict*
getdns_context_get_api_information(getdns_context* context)
{
	getdns_dict* result;
	getdns_dict* settings;

	if ((result = getdns_dict_create_with_context(context))
			
	    && ! getdns_dict_util_set_string(
	    result, "version_string", GETDNS_VERSION)

	    && ! getdns_dict_util_set_string(
	    result, "implementation_string", PACKAGE_URL)

	    && ! getdns_dict_set_int(
	    result, "resolution_type", context->resolution_type)

	    && (settings = _get_context_settings(context))) {

		if (!_getdns_dict_set_this_dict(result,"all_context",settings))
			return result;

		getdns_dict_destroy(settings);
	}
	getdns_dict_destroy(result);
	return NULL;
}

getdns_return_t
getdns_context_set_return_dnssec_status(getdns_context* context, int enabled) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    if (enabled != GETDNS_EXTENSION_TRUE &&
        enabled != GETDNS_EXTENSION_FALSE) {
        return GETDNS_RETURN_INVALID_PARAMETER;
    }
    context->return_dnssec_status = enabled;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_set_use_threads(getdns_context* context, int use_threads) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    int r = 0;
    if (context->resolution_type_set != 0) {
        /* already setup */
        return GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
    }
#ifdef HAVE_LIBUNBOUND
    if (use_threads)
        r = ub_ctx_async(context->unbound_ctx, 1);
    else
        r = ub_ctx_async(context->unbound_ctx, 0);
#else
    (void)use_threads;
#endif
    return r == 0 ? GETDNS_RETURN_GOOD : GETDNS_RETURN_CONTEXT_UPDATE_FAIL;
}

getdns_return_t
_getdns_context_local_namespace_resolve(
    getdns_dns_req *dnsreq, getdns_dict **response)
{
	getdns_context  *context = dnsreq->context;
	host_name_addrs *hnas;
	uint8_t lookup[256];
	getdns_list    empty_list = { 0 };
	getdns_bindata bindata;
	getdns_list   *jaa;
	size_t         i;
	getdns_dict   *addr;
	int ipv4 = dnsreq->netreqs[0]->request_type == GETDNS_RRTYPE_A ||
	    (dnsreq->netreqs[1] &&
	     dnsreq->netreqs[1]->request_type == GETDNS_RRTYPE_A);
	int ipv6 = dnsreq->netreqs[0]->request_type == GETDNS_RRTYPE_AAAA ||
	    (dnsreq->netreqs[1] &&
	     dnsreq->netreqs[1]->request_type == GETDNS_RRTYPE_AAAA);

	if (!ipv4 && !ipv6)
		return GETDNS_RETURN_GENERIC_ERROR;

	/*Do the lookup*/
	(void)memcpy(lookup, dnsreq->name, dnsreq->name_len);
	canonicalize_dname(lookup);

	if (!(hnas = (host_name_addrs *)
	    _getdns_rbtree_search(&context->local_hosts, lookup)))
		return GETDNS_RETURN_GENERIC_ERROR;

	if (!hnas->ipv4addrs && (!ipv6 || !hnas->ipv6addrs))
		return GETDNS_RETURN_GENERIC_ERROR;

	if (!hnas->ipv6addrs && (!ipv4 || !hnas->ipv4addrs))
		return GETDNS_RETURN_GENERIC_ERROR;

	if (!(*response = getdns_dict_create_with_context(context)))
		return GETDNS_RETURN_GENERIC_ERROR;

	bindata.size = dnsreq->name_len;
	bindata.data = dnsreq->name;
	if (getdns_dict_set_bindata(*response, "canonical_name", &bindata))
		goto error;

	empty_list.mf = context->mf;
	if (getdns_dict_set_list(*response, "replies_full", &empty_list))
		goto error;

	if (getdns_dict_set_list(*response, "replies_tree", &empty_list))
		goto error;

	if (getdns_dict_set_int(*response, "status", GETDNS_RESPSTATUS_GOOD))
		goto error;

	if (!ipv4 || !hnas->ipv4addrs) {
		if (getdns_dict_set_list(*response,
		    "just_address_answers", hnas->ipv6addrs))
			goto error;
		return GETDNS_RETURN_GOOD;
	} else if (!ipv6 || !hnas->ipv6addrs) {
		if (getdns_dict_set_list(*response,
		    "just_address_answers", hnas->ipv4addrs))
			goto error;
		return GETDNS_RETURN_GOOD;
	}
	if (!(jaa = getdns_list_create_with_context(context)))
		goto error;

	for (i = 0; !getdns_list_get_dict(hnas->ipv4addrs, i, &addr); i++)
		if (_getdns_list_append_dict(jaa, addr))
			break;
	for (i = 0; !getdns_list_get_dict(hnas->ipv6addrs, i, &addr); i++)
		if (_getdns_list_append_dict(jaa, addr))
			break;
	if (!_getdns_dict_set_this_list(*response, "just_address_answers", jaa))
		return GETDNS_RETURN_GOOD;
	else
		getdns_list_destroy(jaa);
error:
	getdns_dict_destroy(*response);
	return GETDNS_RETURN_GENERIC_ERROR;
}

struct mem_funcs *
priv_getdns_context_mf(getdns_context *context)
{
	return &context->mf;
}

/** begin getters **/
getdns_return_t
getdns_context_get_resolution_type(getdns_context *context,
    getdns_resolution_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->resolution_type;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_namespaces(getdns_context *context,
    size_t* namespace_count, getdns_namespace_t **namespaces) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(namespace_count, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(namespaces, GETDNS_RETURN_INVALID_PARAMETER);
    *namespace_count = context->namespace_count;
    if (!context->namespace_count) {
        *namespaces = NULL;
        return GETDNS_RETURN_GOOD;
    }
    // use normal malloc here so users can do normal free
    *namespaces = malloc(context->namespace_count * sizeof(getdns_namespace_t));
    memcpy(*namespaces, context->namespaces,
           context->namespace_count * sizeof(getdns_namespace_t));
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_dns_transport(getdns_context *context,
    getdns_transport_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
	int count = context->dns_transport_count;
	getdns_transport_list_t *transports = context->dns_transports;
    if (!count)
        return GETDNS_RETURN_WRONG_TYPE_REQUESTED;

    /* Best effort mapping for backwards compatibility*/
    if (transports[0] == GETDNS_TRANSPORT_UDP) {
        if (count == 1) 
            *value = GETDNS_TRANSPORT_UDP_ONLY;
        else if (count == 2 && transports[1] == GETDNS_TRANSPORT_TCP)
            *value = GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP;
        else
            return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
    }
    if (transports[0] == GETDNS_TRANSPORT_TCP) {
        if (count == 1) 
            *value = GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN;
    }
    if (transports[0] == GETDNS_TRANSPORT_TLS) {
        if (count == 1) 
            *value = GETDNS_TRANSPORT_TLS_ONLY_KEEP_CONNECTIONS_OPEN;
        else if (count == 2 && transports[1] == GETDNS_TRANSPORT_TCP)
            *value = GETDNS_TRANSPORT_TLS_FIRST_AND_FALL_BACK_TO_TCP_KEEP_CONNECTIONS_OPEN;
        else
            return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
    }
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_dns_transport_list(getdns_context *context,
    size_t* transport_count, getdns_transport_list_t **transports) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(transport_count, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(transports, GETDNS_RETURN_INVALID_PARAMETER);
   *transport_count = context->dns_transport_count;
    if (!context->dns_transport_count) {
        *transports = NULL;
        return GETDNS_RETURN_GOOD;
    }
    // use normal malloc here so users can do normal free
    *transports = malloc(context->dns_transport_count * sizeof(getdns_transport_list_t));
    memcpy(*transports, context->dns_transports,
           context->dns_transport_count * sizeof(getdns_transport_list_t));
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_tls_authentication(getdns_context *context,
    getdns_tls_authentication_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->tls_auth;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_limit_outstanding_queries(getdns_context *context,
    uint16_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->limit_outstanding_queries;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_timeout(getdns_context *context, uint64_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->timeout;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_idle_timeout(getdns_context *context, uint64_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->idle_timeout;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_follow_redirects(
    getdns_context *context, getdns_redirects_t* value)
{
	if (!context || !value)
		return GETDNS_RETURN_INVALID_PARAMETER;
	*value = context->follow_redirects;
	return GETDNS_RETURN_NOT_IMPLEMENTED;
}

getdns_return_t
getdns_context_get_dns_root_servers(getdns_context *context,
    getdns_list **value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = NULL;
    if (context->dns_root_servers)
        return _getdns_list_copy(context->dns_root_servers, value);
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_append_name(getdns_context *context,
    getdns_append_name_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->append_name;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_suffix(getdns_context *context, getdns_list **value)
{
	size_t dname_len;
	const uint8_t *dname;
	char name[1024];
	getdns_return_t r = GETDNS_RETURN_GOOD;
	getdns_list *list;

	if (!context || !value)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(list = getdns_list_create_with_context(context)))
		return GETDNS_RETURN_MEMORY_ERROR;
	
	assert(context->suffixes);
	dname_len = context->suffixes[0];
	dname = context->suffixes + 1;
	while (dname_len && *dname) {
		if (! gldns_wire2str_dname_buf((UNCONST_UINT8_p)
		    dname, dname_len, name, sizeof(name))) {
			r = GETDNS_RETURN_GENERIC_ERROR;
			break;
		}
		if ((r = _getdns_list_append_string(list, name)))
			break;
		dname += dname_len;
		dname_len = *dname++;
	}
	if (r)
		getdns_list_destroy(list);
	else
		*value = list;

	return r;
}

getdns_return_t
getdns_context_get_dnssec_trust_anchors(
    getdns_context *context, getdns_list **value)
{
	RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
	RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);

	if (context->trust_anchors) {
		if ((*value = getdns_list_create_with_context(context)))
			_getdns_wire2list( context->trust_anchors
			                 , context->trust_anchors_len
			                 , *value);
		else
			return GETDNS_RETURN_MEMORY_ERROR;
	} else
		*value = NULL;

	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_dnssec_allowed_skew(getdns_context *context,
    uint32_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->dnssec_allowed_skew;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_upstream_recursive_servers(getdns_context *context,
    getdns_list **upstreams_r)
{
	size_t i;
	getdns_list *upstreams;
	getdns_return_t r;

	if (!context || !upstreams_r)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(upstreams = getdns_list_create_with_context(context)))
		return GETDNS_RETURN_MEMORY_ERROR;

	if (!context->upstreams || context->upstreams->count == 0) {
		*upstreams_r = upstreams;
		return GETDNS_RETURN_GOOD;
	}
	r = GETDNS_RETURN_GOOD;
	i = 0;
	while (!r && i < context->upstreams->count) {
		size_t j;
		getdns_dict *d;
		getdns_upstream  *upstream = &context->upstreams->upstreams[i];
		getdns_bindata    bindata;
		const getdns_tsig_info *tsig_info;

		if (!(d =
		    sockaddr_dict(context, (struct sockaddr*)&upstream->addr))) {
			r = GETDNS_RETURN_MEMORY_ERROR;
			break;
		}
		if (upstream->tsig_alg) {
			tsig_info = _getdns_get_tsig_info(upstream->tsig_alg);

			if ((r = _getdns_dict_set_const_bindata(
			    d, "tsig_algorithm",
			    tsig_info->dname_len, tsig_info->dname)))
				break;

			if (upstream->tsig_dname_len) {
				bindata.data = upstream->tsig_dname;
				bindata.size = upstream->tsig_dname_len;
				if ((r = getdns_dict_set_bindata(
				    d, "tsig_name", &bindata)))
					break;
			}
			if (upstream->tsig_size) {
				bindata.data = upstream->tsig_key;
				bindata.size = upstream->tsig_size;
				if ((r = getdns_dict_set_bindata(
				    d, "tsig_secret", &bindata)))
					break;
			}
		}
		for ( j = 1, i++
		    ; j < GETDNS_UPSTREAM_TRANSPORTS &&
		      i < context->upstreams->count
		    ; j++, i++) {

			upstream = &context->upstreams->upstreams[i];

			if (upstream->transport == GETDNS_TRANSPORT_UDP &&
			    upstream_port(upstream) != getdns_port_array[j] &&
			    (r = getdns_dict_set_int(d, "port",
			    (uint32_t)upstream_port(upstream))))
				break;

			if (upstream->transport == GETDNS_TRANSPORT_TLS) {
				if (upstream_port(upstream) != getdns_port_array[j] &&
					(r = getdns_dict_set_int(d, "tls_port",
								   (uint32_t) upstream_port(upstream))))
					break;
				if (upstream->tls_auth_name[0] != '\0' &&
				    (r = getdns_dict_util_set_string(d,
				                                     "tls_auth_name",
				                                     upstream->tls_auth_name)))
					break;
				if (upstream->tls_pubkey_pinset) {
					getdns_list *pins = NULL;
					if ((_getdns_get_pubkey_pinset_list(context,
									   upstream->tls_pubkey_pinset,
									   &pins) == GETDNS_RETURN_GOOD) &&
						(r = _getdns_dict_set_this_list(d, "tls_pubkey_pinset", pins))) {
						getdns_list_destroy(pins);
						break;
					}
				}
			}
		}
		if (!r)
			if (!(r = _getdns_list_append_this_dict(upstreams, d)))
				d = NULL;
		getdns_dict_destroy(d);
        }
        if (r)
		getdns_list_destroy(upstreams);
	else
		*upstreams_r = upstreams;
	return r;
}

getdns_return_t
getdns_context_get_edns_maximum_udp_payload_size(getdns_context *context,
    uint16_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->edns_maximum_udp_payload_size;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_edns_extended_rcode(getdns_context *context,
    uint8_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->edns_extended_rcode;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_edns_version(getdns_context *context, uint8_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->edns_version;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_edns_do_bit(getdns_context *context, uint8_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->edns_do_bit;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_edns_client_subnet_private(getdns_context *context, uint8_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->edns_client_subnet_private;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_context_get_tls_query_padding_blocksize(getdns_context *context, uint16_t* value) {
    RETURN_IF_NULL(context, GETDNS_RETURN_INVALID_PARAMETER);
    RETURN_IF_NULL(value, GETDNS_RETURN_INVALID_PARAMETER);
    *value = context->tls_query_padding_blocksize;
    return GETDNS_RETURN_GOOD;
}

/* context.c */
