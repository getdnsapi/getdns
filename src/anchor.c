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
#include <fcntl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <strings.h>
#include <time.h>
#include "types-internal.h"
#include "context.h"
#include "dnssec.h"
#include "yxml/yxml.h"
#include "gldns/parseutil.h"
#include "gldns/gbuffer.h"
#include "gldns/str2wire.h"
#include "gldns/pkthdr.h"
#include "general.h"
#include "rr-iter.h"
#include "util-internal.h"

#define P7SIGNER "dnssec@iana.org"

/* The ICANN CA fetched at 24 Sep 2010.  Valid to 2028 */
static char _getdns_builtin_cert[] = 
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

static getdns_bindata _getdns_builtin_cert_bd =
    { sizeof(_getdns_builtin_cert) - 1, (void *)_getdns_builtin_cert};

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
_getdns_get_valid_signers(PKCS7* p7, const char* p7signer)
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
	validsigners = _getdns_get_valid_signers(p7, p7signer);
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

typedef struct ta_iter {
	uint8_t yxml_buf[4096];
	yxml_t x;

	const char *start;
	const char *ptr;
	const char *end;

	char  zone[1024];

	time_t validFrom;
	time_t validUntil;

	char  keytag[6];
	char  algorithm[4];
	char  digesttype[4];
	char  digest[2048];
} ta_iter;

/**
 * XML convert DateTime element to time_t.
 * [-]CCYY-MM-DDThh:mm:ss[Z|(+|-)hh:mm]
 * (with optional .ssssss fractional seconds)
 * @param str: the string
 * @return a time_t representation or 0 on failure.
 */
static time_t
_getdns_xml_convertdate(const char* str)
{
	time_t t = 0;
	struct tm tm;
	const char* s;
	/* for this application, ignore minus in front;
	 * only positive dates are expected */
	s = str;
	if(s[0] == '-') s++;
	memset(&tm, 0, sizeof(tm));
	/* parse initial content of the string (lots of whitespace allowed) */
	s = strptime(s, "%t%Y%t-%t%m%t-%t%d%tT%t%H%t:%t%M%t:%t%S%t", &tm);
	if(!s) {
		DEBUG_ANCHOR("xml_convertdate parse failure %s\n", str);
		return 0;
	}
	/* parse remainder of date string */
	if(*s == '.') {
		/* optional '.' and fractional seconds */
		int frac = 0, n = 0;
		if(sscanf(s+1, "%d%n", &frac, &n) < 1) {
			DEBUG_ANCHOR("xml_convertdate f failure %s\n", str);
			return 0;
		}
		/* fraction is not used, time_t has second accuracy */
		s++;
		s+=n;
	}
	if(*s == 'Z' || *s == 'z') {
		/* nothing to do for this */
		s++;
	} else if(*s == '+' || *s == '-') {
		/* optional timezone spec: Z or +hh:mm or -hh:mm */
		int hr = 0, mn = 0, n = 0;
		if(sscanf(s+1, "%d:%d%n", &hr, &mn, &n) < 2) {
			DEBUG_ANCHOR("xml_convertdate tz failure %s\n", str);
			return 0;
		}
		if(*s == '+') {
			tm.tm_hour += hr;
			tm.tm_min += mn;
		} else {
			tm.tm_hour -= hr;
			tm.tm_min -= mn;
		}
		s++;
		s += n;
	}
	if(*s != 0) {
		/* not ended properly */
		/* but ignore, (lenient) */
	}

	t = gldns_mktime_from_utc(&tm);
	if(t == (time_t)-1) {
		DEBUG_ANCHOR("xml_convertdate mktime failure\n");
		return 0;
	}
	return t;
}


static inline int ta_iter_done(ta_iter *ta)
{ return *ta->ptr == 0 || ta->ptr >= ta->end; }

static ta_iter *ta_iter_next(ta_iter *ta)
{
	yxml_ret_t r = YXML_OK;
	yxml_t ta_x;
	const char *ta_start;
	int level;
	char value[2048];
	char *cur, *tmp;
	enum { VALIDFROM, VALIDUNTIL } attr_type;
	enum { KEYTAG, ALGORITHM, DIGESTTYPE, DIGEST } elem_type;

	cur = value;
	value[0] = 0;

	if (!ta->zone[0]) {
		DEBUG_ANCHOR("Determine start of <TrustAnchor>\n");
		/* Determine start of <TrustAnchor> */
		while (!ta_iter_done(ta) &&
		    (  yxml_parse(&ta->x, *ta->ptr) != YXML_ELEMSTART
		    || strcasecmp(ta->x.elem, "trustanchor")))
			ta->ptr++;
		if (ta_iter_done(ta)) return NULL;
		ta_start = ta->ptr;
		ta_x = ta->x;

		DEBUG_ANCHOR("Find <Zone>\n");
		/* Find <Zone> */
		level = 0;
		while (!ta_iter_done(ta) && !ta->zone[0]) {
			switch ((r = yxml_parse(&ta->x, *ta->ptr))) {
			case YXML_ELEMSTART:
				level += 1;
				if (level == 1 &&
				    strcasecmp(ta->x.elem, "zone") == 0) {
					cur = value;
					*cur = 0;
				}
				break;

			case YXML_ELEMEND:
				level -= 1;
				if (level < 0)
					/* End of <TrustAnchor> section,
					 * try the next <TrustAnchor> section
					 */
					return ta_iter_next(ta);

				else if (level == 0 && cur) {
					/* <Zone> content ready */
					(void) strncpy( ta->zone, value
					              , sizeof(ta->zone));

					/* Reset to start of <TrustAnchor> */
					cur = NULL;
					ta->ptr = ta_start;
					ta->x = ta_x;
				}
				break;

			case YXML_CONTENT:
				if (!cur || level != 1)
					break;
				tmp = ta->x.data;
				while (*tmp && cur < value + sizeof(value))
					*cur++ = *tmp++;
				if (cur >= value + sizeof(value))
					cur = NULL;
				else
					*cur = 0;
				break;
			default:
				break;
			}
			ta->ptr++;
		}
		if (ta_iter_done(ta))
			return NULL;
	}
	assert(ta->zone[0]);

	DEBUG_ANCHOR("Zone: %s, Find <KeyDigest>\n", ta->zone);
	level = 0;
	while (!ta_iter_done(ta)) {
		r = yxml_parse(&ta->x, *ta->ptr);

		if (r == YXML_ELEMSTART) {
			level += 1;
			DEBUG_ANCHOR("elem start: %s, level: %d\n", ta->x.elem, level);
			if (level == 1 &&
			    strcasecmp(ta->x.elem, "keydigest") == 0)
				break;

		} else if (r == YXML_ELEMEND) {
			level -= 1;
			if (level < 0) {
				/* End of <TrustAnchor> section */
				ta->zone[0] = 0;
				return ta_iter_next(ta);
			}
		}
		ta->ptr++;
	}
	if (ta_iter_done(ta))
		return NULL;

	DEBUG_ANCHOR("Found <KeyDigest>, Parse attributes\n");

	ta->validFrom = ta->validUntil = 0;
	*ta->keytag = *ta->algorithm = *ta->digesttype = *ta->digest = 0;

	cur = NULL;
	value[0] = 0;
	attr_type = -1;

	while (!ta_iter_done(ta)) {
		switch ((r = yxml_parse(&ta->x, *ta->ptr))) {
		case YXML_ELEMSTART:
			break;

		case YXML_ELEMEND:
			/* End of <KeyDigest> section, try next */
			return ta_iter_next(ta);

		case YXML_ATTRSTART:
			DEBUG_ANCHOR("attrstart: %s\n", ta->x.attr);
			if (strcasecmp(ta->x.attr, "validfrom") == 0)
				attr_type = VALIDFROM;

			else if (strcasecmp(ta->x.attr, "validuntil") == 0)
				attr_type = VALIDUNTIL;
			else
				break;

			cur = value;
			*cur = 0;
			break;

		case YXML_ATTREND:
			if (!cur)
				break;
			cur = NULL;
			DEBUG_ANCHOR("attrval: %s\n", value);
			switch (attr_type) {
			case VALIDFROM:
				ta->validFrom = _getdns_xml_convertdate(value);
				break;
			case VALIDUNTIL:
				ta->validUntil = _getdns_xml_convertdate(value);
				break;
			}
			break;

		case YXML_ATTRVAL:
			if (!cur)
				break;
			tmp = ta->x.data;
			while (*tmp && cur < value + sizeof(value))
				*cur++ = *tmp++;
			if (cur >= value + sizeof(value))
				cur = NULL;
			else
				*cur = 0;
			break;
		case YXML_OK:
		case YXML_CONTENT:
			break;
		default:
			DEBUG_ANCHOR("r: %d\n", (int)r);
			return NULL;
			break;
		}
		if (r == YXML_ELEMSTART)
			break;
		ta->ptr++;
	}
	if (ta_iter_done(ta))
		return NULL;

	assert(r == YXML_ELEMSTART);
	DEBUG_ANCHOR("Within <KeyDigest>, Parse child elements\n");

	cur = NULL;
	value[0] = 0;
	elem_type = -1;

	for (;;) {
		switch (r) {
		case YXML_ELEMSTART:
			level += 1;
			DEBUG_ANCHOR("elem start: %s, level: %d\n", ta->x.elem, level);
			if (level != 2)
				break;

			else if (strcasecmp(ta->x.elem, "keytag") == 0)
				elem_type = KEYTAG;

			else if (strcasecmp(ta->x.elem, "algorithm") == 0)
				elem_type = ALGORITHM;

			else if (strcasecmp(ta->x.elem, "digesttype") == 0)
				elem_type = DIGESTTYPE;

			else if (strcasecmp(ta->x.elem, "digest") == 0)
				elem_type = DIGEST;
			else
				break;

			cur = value;
			*cur = 0;
			break;

		case YXML_ELEMEND:
			level -= 1;
			if (level < 0) {
				/* End of <TrustAnchor> section */
				ta->zone[0] = 0;
				return ta_iter_next(ta);

			} else if (level != 1 || !cur)
				break;

			cur = NULL;
			DEBUG_ANCHOR("elem end: %s\n", value);
			switch (elem_type) {
			case KEYTAG:
				(void) strncpy( ta->keytag, value
				              , sizeof(ta->keytag));
				break;
			case ALGORITHM:
				(void) strncpy( ta->algorithm, value
				              , sizeof(ta->algorithm));
				break;
			case DIGESTTYPE:
				(void) strncpy( ta->digesttype, value
				              , sizeof(ta->digesttype));
				break;
			case DIGEST:
				(void) strncpy( ta->digest, value
				              , sizeof(ta->digest));
				break;
			}
			break;

		case YXML_CONTENT:
			if (!cur)
				break;
			tmp = ta->x.data;
			while (*tmp && cur < value + sizeof(value))
				*cur++ = *tmp++;
			if (cur >= value + sizeof(value))
				cur = NULL;
			else
				*cur = 0;
			break;

		default:
			break;
		}
		if (level == 0)
			break;
		ta->ptr++;
		if (ta_iter_done(ta))
			return NULL;
		r = yxml_parse(&ta->x, *ta->ptr);
	}
	return  ta->validFrom
	    && *ta->keytag     && *ta->algorithm
	    && *ta->digesttype && *ta->digest ? ta : ta_iter_next(ta);
}

static ta_iter *ta_iter_init(ta_iter *ta, const char *doc, size_t doc_len)
{
	ta->ptr = ta->start = doc;
	ta->end = ta->start + doc_len;
	yxml_init(&ta->x, ta->yxml_buf, sizeof(ta->yxml_buf));
	ta->zone[0] = 0;
	return ta_iter_next(ta);
}

uint16_t _getdns_parse_xml_trust_anchors_buf(
    gldns_buffer *gbuf, time_t now, char *xml_data, size_t xml_len)
{
	ta_iter ta_spc, *ta;
	uint16_t ta_count = 0;
	size_t pkt_start = gldns_buffer_position(gbuf);

	/* Empty header */
	gldns_buffer_write_u32(gbuf, 0);
	gldns_buffer_write_u32(gbuf, 0);
	gldns_buffer_write_u32(gbuf, 0);

	for ( ta = ta_iter_init(&ta_spc, (char *)xml_data, xml_len)
	    ; ta; ta = ta_iter_next(ta)) {

		if (now < ta->validFrom)
			DEBUG_ANCHOR("Disregarding trust anchor "
			    "%s for %s which is not yet valid",
			    ta->keytag, ta->zone);

		else if (ta->validUntil != 0 && now > ta->validUntil)
			DEBUG_ANCHOR("Disregarding trust anchor "
			    "%s for %s which is not valid anymore",
			    ta->keytag, ta->zone);

		else {
			uint8_t zone[256];
			size_t zone_len = sizeof(zone);
			uint8_t digest[sizeof(ta->digest)/2];
			size_t digest_len = sizeof(digest);
			uint16_t keytag;
			uint8_t algorithm;
			uint8_t digesttype;
			char *endptr;

			DEBUG_ANCHOR( "Installing trust anchor: "
			    "%s IN DS %s %s %s %s\n"
			    , ta->zone
			    , ta->keytag
			    , ta->algorithm
			    , ta->digesttype
			    , ta->digest
			    );
			if (gldns_str2wire_dname_buf(ta->zone, zone, &zone_len)) {
				DEBUG_ANCHOR("Not installing trust anchor because "
				    "of unparsable zone: \"%s\"", ta->zone);
				continue;
			}
			keytag = (uint16_t)strtol(ta->keytag, &endptr, 10);
			if (endptr == ta->keytag || *endptr != 0) {
				DEBUG_ANCHOR("Not installing trust anchor because "
				    "of unparsable keytag: \"%s\"", ta->keytag);
				continue;
			}
			algorithm = (uint16_t)strtol(ta->algorithm, &endptr, 10);
			if (endptr == ta->algorithm || *endptr != 0) {
				DEBUG_ANCHOR("Not installing trust anchor because "
				    "of unparsable algorithm: \"%s\"", ta->algorithm);
				continue;
			}
			digesttype = (uint16_t)strtol(ta->digesttype, &endptr, 10);
			if (endptr == ta->digesttype || *endptr != 0) {
				DEBUG_ANCHOR("Not installing trust anchor because "
				    "of unparsable digesttype: \"%s\"", ta->digesttype);
				continue;
			}
			if (gldns_str2wire_hex_buf(ta->digest, digest, &digest_len)) {
				DEBUG_ANCHOR("Not installing trust anchor because "
				    "of unparsable digest: \"%s\"", ta->digest);
				continue;
			}
			gldns_buffer_write(gbuf, zone, zone_len);
			gldns_buffer_write_u16(gbuf, GETDNS_RRTYPE_DS);
			gldns_buffer_write_u16(gbuf, GETDNS_RRCLASS_IN);
			gldns_buffer_write_u32(gbuf, 3600);
			gldns_buffer_write_u16(gbuf, digest_len + 4); /* rdata_len */
			gldns_buffer_write_u16(gbuf, keytag);
			gldns_buffer_write_u8(gbuf, algorithm);
			gldns_buffer_write_u8(gbuf, digesttype);
			gldns_buffer_write(gbuf, digest, digest_len);
			ta_count += 1;
		}
	}
	gldns_buffer_write_u16_at(gbuf, pkt_start+GLDNS_ANCOUNT_OFF, ta_count);
	return ta_count;
}

static uint8_t *tas_validate(struct mem_funcs *mf,
    const getdns_bindata *xml_bd, const getdns_bindata *p7s_bd,
    const getdns_bindata *crt_bd, const char *p7signer,
    time_t now, uint8_t *tas, size_t *tas_len)
{
	BIO *xml = NULL, *p7s = NULL, *crt = NULL;
	X509 *x = NULL;
	X509_STORE *store = NULL;
	uint8_t *success = NULL;

	if (!(xml = BIO_new_mem_buf(xml_bd->data, xml_bd->size)))
		DEBUG_ANCHOR("ERROR %s(): Failed allocating xml BIO\n"
		            , __FUNC__);

	else if (!(p7s = BIO_new_mem_buf(p7s_bd->data, p7s_bd->size)))
		DEBUG_ANCHOR("ERROR %s(): Failed allocating p7s BIO\n"
		            , __FUNC__);
	
	else if (!(crt = BIO_new_mem_buf(crt_bd->data, crt_bd->size)))
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

	else if (_getdns_verify_p7sig(xml, p7s, store, p7signer)) {
		gldns_buffer gbuf;

		gldns_buffer_init_vfixed_frm_data(&gbuf, tas, *tas_len);

		if (!_getdns_parse_xml_trust_anchors_buf(&gbuf, now, 
		    (char *)xml_bd->data, xml_bd->size))
			DEBUG_ANCHOR("Failed to parse trust anchor XML data");

		else if (gldns_buffer_position(&gbuf) > *tas_len) {
			*tas_len = gldns_buffer_position(&gbuf);
			if ((success = GETDNS_XMALLOC(*mf, uint8_t, *tas_len))) {
				gldns_buffer_init_frm_data(&gbuf, success, *tas_len);
				if (!_getdns_parse_xml_trust_anchors_buf(&gbuf,
				    now, (char *)xml_bd->data, xml_bd->size)) {

					DEBUG_ANCHOR("Failed to re-parse trust"
					             " anchor XML data\n");
					GETDNS_FREE(*mf, success);
					success = NULL;
				}
			} else
				DEBUG_ANCHOR("Could not allocate space for "
				             "trust anchors\n");
		} else {
			success = tas;
			*tas_len = gldns_buffer_position(&gbuf);
		}
	} else {
		DEBUG_ANCHOR("Verifying trust-anchors failed!\n");
	}
	if (store)	X509_STORE_free(store);
	if (x)		X509_free(x);
	if (crt)	BIO_free(crt);
	if (xml)	BIO_free(xml);
	if (p7s)	BIO_free(p7s);
	return success;
}

void _getdns_context_equip_with_anchor(getdns_context *context, time_t now)
{
	uint8_t xml_spc[4096], *xml_data;
	uint8_t p7s_spc[4096], *p7s_data = NULL;
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
	
	else if (!(crt = BIO_new_mem_buf((void *)_getdns_builtin_cert, -1)))
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
		uint8_t ta_spc[sizeof(context->trust_anchors_spc)];
		size_t ta_len;
		uint8_t *ta = NULL;
		gldns_buffer gbuf;

		gldns_buffer_init_vfixed_frm_data(
		    &gbuf, ta_spc, sizeof(ta_spc));

		if (!_getdns_parse_xml_trust_anchors_buf(&gbuf, now, 
		    (char *)xml_data, xml_len))
			DEBUG_ANCHOR("Failed to parse trust anchor XML data");
		else if ((ta_len = gldns_buffer_position(&gbuf)) > sizeof(ta_spc)) {
			if ((ta = GETDNS_XMALLOC(context->mf, uint8_t, ta_len))) {
				gldns_buffer_init_frm_data(&gbuf, ta,
				    gldns_buffer_position(&gbuf));
				if (!_getdns_parse_xml_trust_anchors_buf(
				    &gbuf, now, (char *)xml_data, xml_len)) {
					DEBUG_ANCHOR("Failed to re-parse trust"
					             " anchor XML data");
					GETDNS_FREE(context->mf, ta);
				} else {
					context->trust_anchors = ta;
					context->trust_anchors_len = ta_len;
					context->trust_anchors_source = GETDNS_TASRC_XML;
				}
			} else
				DEBUG_ANCHOR("Could not allocate space for XML file");
		} else {
			(void)memcpy(context->trust_anchors_spc, ta_spc, ta_len);
			context->trust_anchors = context->trust_anchors_spc;
			context->trust_anchors_len = ta_len;
			context->trust_anchors_source = GETDNS_TASRC_XML;
		}
		DEBUG_ANCHOR("ta: %p, ta_len: %d\n", context->trust_anchors, (int)context->trust_anchors_len);
		
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

#if 0
static const uint8_t tas_write_xml_buf[] =
"GET /root-anchors/root-anchors.xml HTTP/1.1\r\n"
"Host: data.iana.org\r\n"
"\r\n";
#endif

static const uint8_t tas_write_p7s_buf[] =
"GET /root-anchors/root-anchors.p7s HTTP/1.1\r\n"
"Host: data.iana.org\r\n"
"\r\n";

static const uint8_t tas_write_xml_p7s_buf[] =
"GET /root-anchors/root-anchors.xml HTTP/1.1\r\n"
"Host: data.iana.org\r\n"
"\r\n"
"GET /root-anchors/root-anchors.p7s HTTP/1.1\r\n"
"Host: data.iana.org\r\n"
"\r\n";


#if defined(ANCHOR_DEBUG) && ANCHOR_DEBUG
static inline const char * rt_str(uint16_t rt)
{ return rt == GETDNS_RRTYPE_A ? "A" : rt == GETDNS_RRTYPE_AAAA ? "AAAA" : "?"; }
#endif

static int tas_busy(tas_connection *a)
{
	return a->req != NULL;
}

static void tas_cleanup(getdns_context *context, tas_connection *a)
{
	if (a->req)
		_getdns_context_cancel_request(a->req->owner);
	if (a->event.ev)
		GETDNS_CLEAR_EVENT(a->loop, &a->event);
	if (a->fd >= 0)
		close(a->fd);
	if (a->xml.data)
		GETDNS_FREE(context->mf, a->xml.data);
	if (a->tcp.read_buf && a->tcp.read_buf != context->tas_hdr_spc)
		GETDNS_FREE(context->mf, a->tcp.read_buf);
	(void) memset(a, 0, sizeof(*a));
	a->fd = -1;
}

static void tas_success(getdns_context *context, tas_connection *a)
{
	tas_connection *other = &context->a == a ? &context->aaaa : &context->a;

	tas_cleanup(context, a);
	tas_cleanup(context, other);

	DEBUG_ANCHOR("Successfully fetched new trust anchors\n");
	context->trust_anchors_source = GETDNS_TASRC_XML;
	_getdns_ta_notify_dnsreqs(context);
}

static void tas_fail(getdns_context *context, tas_connection *a)
{
	tas_connection *other = &context->a == a ? &context->aaaa : &context->a;
#if defined(ANCHOR_DEBUG) && ANCHOR_DEBUG
	uint16_t rt = &context->a == a ? GETDNS_RRTYPE_A : GETDNS_RRTYPE_AAAA;
	uint16_t ort = rt == GETDNS_RRTYPE_A ? GETDNS_RRTYPE_AAAA : GETDNS_RRTYPE_A;
#endif
	tas_cleanup(context, a);

	if (!tas_busy(other)) {
		DEBUG_ANCHOR("Fatal error fetching trust anchor: "
		             "%s connection failed too\n", rt_str(rt));
		context->trust_anchors_source = GETDNS_TASRC_FAILED;
		_getdns_ta_notify_dnsreqs(context);
	} else
		DEBUG_ANCHOR("%s connection failed, waiting for %s\n"
		            , rt_str(rt), rt_str(ort));
}

static void tas_connect(getdns_context *context, tas_connection *a);
static void tas_next(getdns_context *context, tas_connection *a)
{
	DEBUG_ANCHOR("Try next address\n");
	if (!(a->rr = _getdns_rrtype_iter_next(a->rr)))
		tas_fail(context, a);
	else	tas_connect(context, a);
}

static void tas_timeout_cb(void *userarg)
{
	getdns_dns_req *dnsreq = (getdns_dns_req *)userarg;
	getdns_context *context = (getdns_context *)dnsreq->user_pointer;
	tas_connection *a;

	if (dnsreq->netreqs[0]->request_type == GETDNS_RRTYPE_A)
		a = &context->a;
	else	a = &context->aaaa;

	DEBUG_ANCHOR("Trust anchor fetch timeout\n");
	GETDNS_CLEAR_EVENT(a->loop, &a->event);
	tas_next(context, a);
}

static void tas_read_cb(void *userarg);
static void tas_write_cb(void *userarg);
static void tas_doc_read(getdns_context *context, tas_connection *a)
{
	DEBUG_ANCHOR("doc (size: %d): \"%.*s\"\n",
	    (int)a->tcp.read_buf_len,
	    (int)a->tcp.read_buf_len, (char *)a->tcp.read_buf);

	assert(a->tcp.read_pos == a->tcp.read_buf + a->tcp.read_buf_len);

	if (a->state == TAS_READ_XML_DOC) {
		if (a->xml.data)
			GETDNS_FREE(context->mf, a->xml.data);
		a->xml.data = a->tcp.read_buf;
		a->xml.size = a->tcp.read_buf_len;
	} else
		assert(a->state == TAS_READ_PS7_DOC);

	a->state += 1;
	GETDNS_CLEAR_EVENT(a->loop, &a->event);
	if (a->state == TAS_DONE) {
		getdns_bindata p7s_bd;
		uint8_t *tas = context->trust_anchors_spc;
		size_t tas_len = sizeof(context->trust_anchors_spc);

		p7s_bd.data = a->tcp.read_buf;
		p7s_bd.size = a->tcp.read_buf_len;
	       	tas = tas_validate(&context->mf, &a->xml, &p7s_bd,
		    &_getdns_builtin_cert_bd, "dnssec@iana.org",
		    time(NULL), tas, &tas_len);

		if (tas) {
			context->trust_anchors = tas;
			context->trust_anchors_len = tas_len;
			/* TODO: Try to write xml & p7s */
			tas_success(context, a);
		} else
			tas_fail(context, a);
		return;
	}
	assert(a->state == TAS_WRITE_GET_PS7);
	a->tcp.write_buf = tas_write_p7s_buf;
	a->tcp.write_buf_len = sizeof(tas_write_p7s_buf) - 1;
	a->tcp.written = 0;

	/* First try to read signatures immediately */
	a->state += 1;
	assert(a->state == TAS_READ_PS7_HDR);
	a->tcp.read_buf = context->tas_hdr_spc;
	a->tcp.read_buf_len = sizeof(context->tas_hdr_spc);

	/* Check for surplus read bytes, for the P7S headers */
	if (a->tcp.to_read > 0) {
		a->tcp.read_pos = a->tcp.read_buf + a->tcp.to_read;
		a->tcp.to_read  = sizeof(context->tas_hdr_spc)
		                                  - a->tcp.to_read;
	} else {
		a->tcp.read_pos = a->tcp.read_buf;
		a->tcp.to_read = sizeof(context->tas_hdr_spc);
	}
	GETDNS_SCHEDULE_EVENT(a->loop, a->fd, 50,
	    getdns_eventloop_event_init(&a->event, a->req->owner,
	    tas_read_cb, NULL, tas_timeout_cb));
#if 0
	GETDNS_SCHEDULE_EVENT(a->loop, a->fd, 2000,
	    getdns_eventloop_event_init(&a->event, a->req->owner,
	    NULL, tas_write_cb, tas_timeout_cb));
#endif
	return;
}

static void tas_read_cb(void *userarg)
{
	getdns_dns_req *dnsreq = (getdns_dns_req *)userarg;
	getdns_context *context = (getdns_context *)dnsreq->user_pointer;
	tas_connection *a;
	ssize_t n, i;

	if (dnsreq->netreqs[0]->request_type == GETDNS_RRTYPE_A)
		a = &context->a;
	else	a = &context->aaaa;

	DEBUG_ANCHOR( "state: %d, to_read: %d\n"
	            , (int)a->state, (int)a->tcp.to_read);

	n = read(a->fd, a->tcp.read_pos, a->tcp.to_read);
	if (n >= 0 && (  a->state == TAS_READ_XML_DOC
	              || a->state == TAS_READ_PS7_DOC)) {

		assert(n <= (ssize_t)a->tcp.to_read);

		DEBUG_ANCHOR("read: %d bytes at %p, for doc %p of size %d\n",
		    (int)n, a->tcp.read_pos, a->tcp.read_buf, (int)a->tcp.read_buf_len);
		a->tcp.read_pos += n;
		a->tcp.to_read -= n;
		if (a->tcp.to_read == 0)
			tas_doc_read(context, a);
		return;

	} else if (n >= 0) {
		ssize_t p = 0;
		int doc_len = -1;
		int len;
		char *ln;
		char *endptr;

		n += a->tcp.read_pos - a->tcp.read_buf;
		for (i = 0; i < (n - 1); i++) {
			if (a->tcp.read_buf[i] != '\r' ||
			    a->tcp.read_buf[i+1] != '\n')
				continue;

			len = (int)(i - p);
			ln = (char *)&a->tcp.read_buf[p];

			DEBUG_ANCHOR("line: \"%.*s\"\n", len, ln);
			if (len >= 16 &&
			    !strncasecmp(ln, "Content-Length: ", 16)) {
				ln[len] = 0;
				doc_len = (int)strtol(ln + 16, &endptr , 10);
				if (endptr == ln || *endptr != 0)
					doc_len = -1;
			}
			if (i - p == 0) {
				i += 2;
				break;
			}
			p = i + 2;
			i++;
		}
		if (doc_len > 0) {
			uint8_t *doc = GETDNS_XMALLOC(
			    context->mf, uint8_t, doc_len);

			DEBUG_ANCHOR("i: %d, n: %d, doc_len: %d\n"
			            , (int)i, (int)n, doc_len);
			if (!doc)
				DEBUG_ANCHOR("Memory error");
			else {
				ssize_t surplus = n - i;

				a->state += 1;
				/* With pipelined read, the buffer might
				 * contain the full document, plus a piece
				 * of the headers of the next document!
				 * Currently context->tas_hdr_spc is kept
				 * small enough to anticipate this.
				 */
				if (surplus <= 0) {
					a->tcp.read_pos = doc;
					a->tcp.to_read = doc_len;
				} else if (surplus > doc_len) {
					(void) memcpy(
					    doc, a->tcp.read_buf + i, doc_len);
					a->tcp.read_pos = doc + doc_len;

					/* Special value to indicate a begin
					 * of the next reply is already
					 * present.  Detectable by:
					 * (read_pos == read_buf + read_buf_len)
					 * && to_read > 0;
					 */
					a->tcp.to_read = surplus - doc_len;
					(void) memmove(a->tcp.read_buf,
					    a->tcp.read_buf + i + doc_len,
					    surplus - doc_len);
				} else {
					assert(surplus <= doc_len);
					(void) memcpy(
					    doc, a->tcp.read_buf + i, surplus);
					a->tcp.read_pos = doc + surplus;
					a->tcp.to_read = doc_len - surplus;
				}
				a->tcp.read_buf = doc;
				a->tcp.read_buf_len = doc_len;

				if (a->tcp.read_pos == doc + doc_len)
					tas_doc_read(context, a);
				return;
			}
		}
	} else if (_getdns_EWOULDBLOCK)
		return;

	DEBUG_ANCHOR("Read error: %s\n", strerror(errno));
	GETDNS_CLEAR_EVENT(a->loop, &a->event);
	tas_next(context, a);
}

static void tas_write_cb(void *userarg)
{
	getdns_dns_req *dnsreq = (getdns_dns_req *)userarg;
	getdns_context *context = (getdns_context *)dnsreq->user_pointer;
	tas_connection *a;
	ssize_t written;

	if (dnsreq->netreqs[0]->request_type == GETDNS_RRTYPE_A)
		a = &context->a;
	else	a = &context->aaaa;

	DEBUG_ANCHOR( "state: %d, to_write: %d\n"
	            , (int)a->state, (int)a->tcp.write_buf_len);

	written = write(a->fd, a->tcp.write_buf, a->tcp.write_buf_len);
	if (written >= 0) {
		assert(written <= (ssize_t)a->tcp.write_buf_len);

		a->tcp.write_buf += written;
		a->tcp.write_buf_len -= written;
		if (a->tcp.write_buf_len > 0)
			/* Write remainder */
			return;

		a->state += 1;
		a->tcp.read_buf = context->tas_hdr_spc;
		a->tcp.read_buf_len = sizeof(context->tas_hdr_spc);
		a->tcp.read_pos = a->tcp.read_buf;
		a->tcp.to_read = sizeof(context->tas_hdr_spc);
		GETDNS_CLEAR_EVENT(a->loop, &a->event);
		DEBUG_ANCHOR("All written, schedule read\n");
		GETDNS_SCHEDULE_EVENT(a->loop, a->fd, 2000,
		    getdns_eventloop_event_init(&a->event, a->req->owner,
		    tas_read_cb, NULL, tas_timeout_cb));
		return;

	} else if (_getdns_EWOULDBLOCK)
		return;

	DEBUG_ANCHOR("Write error: %s\n", strerror(errno));
	GETDNS_CLEAR_EVENT(a->loop, &a->event);
	tas_next(context, a);
}

static void tas_connect(getdns_context *context, tas_connection *a)
{
#if defined(ANCHOR_DEBUG) && ANCHOR_DEBUG
	char a_buf[40];
#endif
	int r;

#ifdef HAVE_FCNTL
	int flag;
#elif defined(HAVE_IOCTLSOCKET)
	unsigned long on = 1;
#endif

	if (a->rr->rr_i.nxt - (a->rr->rr_i.rr_type + 10) !=
	    ( a->req->request_type == GETDNS_RRTYPE_A    ?  4
	    : a->req->request_type == GETDNS_RRTYPE_AAAA ? 16 : -1)) {

		tas_next(context, a);
		return;
	}
	DEBUG_ANCHOR("Initiating connection to %s\n"
		    , inet_ntop(( a->req->request_type == GETDNS_RRTYPE_A
				? AF_INET : AF_INET6)
	            , a->rr->rr_i.rr_type + 10, a_buf, sizeof(a_buf)));

	if ((a->fd = socket(( a->req->request_type == GETDNS_RRTYPE_A
	    ? AF_INET : AF_INET6), SOCK_STREAM, IPPROTO_TCP)) == -1) {
		DEBUG_ANCHOR("Error creating socket: %s\n", strerror(errno));
		tas_next(context, a);
		return;
	}
#ifdef HAVE_FCNTL
	if((flag = fcntl(a->fd, F_GETFL)) != -1) {
		flag |= O_NONBLOCK;
		if(fcntl(a->fd, F_SETFL, flag) == -1) {
			/* ignore error, continue blockingly */
		}
	}
#elif defined(HAVE_IOCTLSOCKET)
	if(ioctlsocket(a->fd, FIONBIO, &on) != 0) {
		/* ignore error, continue blockingly */
	}
#endif
	if (a->req->request_type == GETDNS_RRTYPE_A) {
		struct sockaddr_in addr;

		addr.sin_family = AF_INET;
		addr.sin_port = htons(80);
		(void) memcpy(&addr.sin_addr, a->rr->rr_i.rr_type + 10, 4);
		r = connect(a->fd, (struct sockaddr *)&addr, sizeof(addr));
	} else {
		struct sockaddr_in6 addr;

		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(80);
		addr.sin6_flowinfo = 0;
		(void) memcpy(&addr.sin6_addr, a->rr->rr_i.rr_type + 10, 16);
		addr.sin6_scope_id = 0;
		r = connect(a->fd, (struct sockaddr *)&addr, sizeof(addr));
	}
	if (r == 0 || (r == -1 && (_getdns_EINPROGRESS ||
				   _getdns_EWOULDBLOCK))) {

		a->state += 1;
		a->tcp.write_buf = tas_write_xml_p7s_buf;
		a->tcp.write_buf_len = sizeof(tas_write_xml_p7s_buf) - 1;
		a->tcp.written = 0;

		GETDNS_SCHEDULE_EVENT(a->loop, a->fd, 2000,
		    getdns_eventloop_event_init(&a->event, a->req->owner,
		    NULL, tas_write_cb, tas_timeout_cb));
		DEBUG_ANCHOR("Scheduled write\n");
		return;
	} else
		DEBUG_ANCHOR("Connect error: %s\n", strerror(errno));

	tas_next(context, a);
}

static void data_iana_org(getdns_dns_req *dnsreq)
{
	getdns_context *context = (getdns_context *)dnsreq->user_pointer;
	tas_connection *a;
       
	if (dnsreq->netreqs[0]->request_type == GETDNS_RRTYPE_A)
		a = &context->a;
	else	a = &context->aaaa;

	a->rrset = _getdns_rrset_answer(
	    &a->rrset_spc, a->req->response, a->req->response_len);

	if (!a->rrset)
		DEBUG_ANCHOR("%s lookup for data.iana.org. returned no "
		             "response\n", rt_str(a->req->request_type));

	else if (a->req->response_len < dnsreq->name_len + 12 ||
	    !_getdns_dname_equal(a->req->response + 12, dnsreq->name) ||
	    a->rrset->rr_type != a->req->request_type)
		DEBUG_ANCHOR("%s lookup for data.iana.org. returned wrong "
		             "response\n", rt_str(a->req->request_type));
	else  if (!(a->rr = _getdns_rrtype_iter_init(&a->rr_spc, a->rrset)))
		DEBUG_ANCHOR("%s lookup for data.iana.org. returned no "
		             "addresses\n", rt_str(a->req->request_type));
	else {
		a->loop = dnsreq->loop;
		tas_connect(context, a);
		return;
	}
	tas_fail(context, a);
}

void _getdns_start_fetching_ta(getdns_context *context, getdns_eventloop *loop)
{
	getdns_return_t r;
	size_t scheduled;

	DEBUG_ANCHOR("%s on the %ssynchronous loop\n", __FUNC__,
	             loop == &context->sync_eventloop.loop ? "" : "a");

	while (!context->sys_ctxt) {
		if ((r = getdns_context_create_with_extended_memory_functions(
		    &context->sys_ctxt, 1, context->mf.mf_arg,
		    context->mf.mf.ext.malloc, context->mf.mf.ext.realloc,
		    context->mf.mf.ext.free)))
			DEBUG_ANCHOR("Could not create system context: %s\n"
			            , getdns_get_errorstr_by_id(r));

		else if ((r = getdns_context_set_eventloop(
		    context->sys_ctxt, loop)))
			DEBUG_ANCHOR("Could not configure %ssynchronous loop "
			             "with system context: %s\n"
			            , ( loop == &context->sync_eventloop.loop
			              ? "" : "a" )
			            , getdns_get_errorstr_by_id(r));

		else if ((r = getdns_context_set_resolution_type(
		    context->sys_ctxt, GETDNS_RESOLUTION_STUB)))
			DEBUG_ANCHOR("Could not configure system context for "
			             "stub resolver: %s\n"
			            , getdns_get_errorstr_by_id(r));
		else
			break;

		getdns_context_destroy(context->sys_ctxt);
		context->sys_ctxt = NULL;
		DEBUG_ANCHOR("Fatal error fetching trust anchor: "
		             "missing system context\n");
		context->trust_anchors_source = GETDNS_TASRC_FAILED;
		_getdns_ta_notify_dnsreqs(context);
		return;
	}
	scheduled = 0;
#if 1
	context->a.state = TAS_LOOKUP_ADDRESSES;
	if ((r = _getdns_general_loop(context->sys_ctxt, loop,
	    "data.iana.org.", GETDNS_RRTYPE_A, NULL, context,
	    &context->a.req, NULL, data_iana_org))) {
		DEBUG_ANCHOR("Error scheduling A lookup for data.iana.org: "
		             "%s\n", getdns_get_errorstr_by_id(r));
	} else
		scheduled += 1;
#endif

#if 0
	context->aaaa.state = TAS_LOOKUP_ADDRESSES;
	if ((r = _getdns_general_loop(context->sys_ctxt, loop,
	    "data.iana.org.", GETDNS_RRTYPE_AAAA, NULL, context,
	    &context->aaaa.req, NULL, data_iana_org))) {
		DEBUG_ANCHOR("Error scheduling AAAA lookup for data.iana.org: "
		             "%s\n", getdns_get_errorstr_by_id(r));
	} else
		scheduled += 1;
#endif

	if (!scheduled) {
		DEBUG_ANCHOR("Fatal error fetching trust anchor: Unable to "
		             "schedule address requests for data.iana.org\n");
		context->trust_anchors_source = GETDNS_TASRC_FAILED;
		_getdns_ta_notify_dnsreqs(context);
	} else
		context->trust_anchors_source = GETDNS_TASRC_FETCHING;
}

/* anchor.c */
