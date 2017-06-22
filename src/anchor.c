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
#include "yxml/yxml.h"
#include "gldns/parseutil.h"
#include "gldns/gbuffer.h"
#include "gldns/str2wire.h"
#include "gldns/pkthdr.h"

#define P7SIGNER "dnssec@iana.org"

/* The ICANN CA fetched at 24 Sep 2010.  Valid to 2028 */
static char* _getdns_builtin_cert = 
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
	yxml_ret_t r;
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

void _getdns_context_equip_with_anchor(getdns_context *context, time_t now)
{
	uint8_t xml_spc[4096], *xml_data = xml_spc;
	uint8_t p7s_spc[4096], *p7s_data = p7s_spc;
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

/* anchor.c */
