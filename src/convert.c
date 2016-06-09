/**
 *
 * \file convert.c
 * @brief getdns label conversion functions
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

#include <stdio.h>
#include <string.h>
#include <locale.h>
#include "config.h"
#ifndef USE_WINSOCK
#include <arpa/inet.h>
#endif
#ifdef HAVE_LIBIDN
#include <stringprep.h>
#include <idna.h>
#endif
#include "getdns/getdns.h"
#include "getdns/getdns_extra.h"
#include "util-internal.h"
#include "gldns/wire2str.h"
#include "gldns/str2wire.h"
#include "dict.h"
#include "list.h"
#include "convert.h"

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

getdns_return_t
getdns_convert_dns_name_to_fqdn(
    const getdns_bindata *dns_name_wire_fmt, char **fqdn_as_string)
{
	char *r;

	if (!dns_name_wire_fmt || !fqdn_as_string)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(r = gldns_wire2str_dname(
	    dns_name_wire_fmt->data, dns_name_wire_fmt->size)))
		return GETDNS_RETURN_GENERIC_ERROR;

	*fqdn_as_string = r;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_convert_fqdn_to_dns_name(
    const char *fqdn_as_string, getdns_bindata **dns_name_wire_fmt)
{
	getdns_bindata *r;
	uint8_t *dname;
	size_t len;

	if (!fqdn_as_string || !dns_name_wire_fmt)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(r = malloc(sizeof(getdns_bindata))))
		return GETDNS_RETURN_MEMORY_ERROR;

	if (!(dname = gldns_str2wire_dname(fqdn_as_string, &len))) {
		free(r);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	r->size = len;
	r->data = dname;
	*dns_name_wire_fmt = r;
	return GETDNS_RETURN_GOOD;
}

/*---------------------------------------- getdns_convert_alabel_to_ulabel */
/**
 * Convert UTF-8 string into an ACE-encoded domain
 * It is the application programmer's responsibility to free()
 * the returned buffer after use
 *
 * @param ulabel the UTF-8-encoded domain name to convert
 * @return pointer to ACE-encoded string
 * @return NULL if conversion fails
 */

char *
getdns_convert_ulabel_to_alabel(const char *ulabel)
{
#ifdef HAVE_LIBIDN
    int ret;
    char *buf;
    char *prepped;
    char *prepped2;

    if (ulabel == NULL)
	return 0;
    prepped2 = malloc(BUFSIZ);
    if(!prepped2)
	    return 0;
    setlocale(LC_ALL, "");
    if ((prepped = stringprep_locale_to_utf8(ulabel)) == 0) {
	/* convert to utf8 fails, which it can, but continue anyway */
	if(strlen(ulabel)+1 > BUFSIZ) {
	    free(prepped2);
	    return 0;
	}
	memcpy(prepped2, ulabel, strlen(ulabel)+1);
    } else {
	if(strlen(prepped)+1 > BUFSIZ) {
	    free(prepped);
	    free(prepped2);
	    return 0;
	}
	memcpy(prepped2, prepped, strlen(prepped)+1);
	free(prepped);
    }
    if ((ret = stringprep(prepped2, BUFSIZ, 0, stringprep_nameprep)) != STRINGPREP_OK) {
	free(prepped2);
	return 0;
    }
    if ((ret = idna_to_ascii_8z(prepped2, &buf, 0)) != IDNA_SUCCESS)  {
	free(prepped2);
	return 0;
    }
    free(prepped2);
    return buf;
#else
    return NULL;
#endif
}

/*---------------------------------------- getdns_convert_alabel_to_ulabel */
/**
 * Convert ACE-encoded domain name into a UTF-8 string.
 * It is the application programmer's responsibility to free()
 * the returned buffer after use
 *
 * @param alabel the ACE-encoded domain name to convert
 * @return pointer to UTF-8 string
 * @return NULL if conversion fails
 */

char *
getdns_convert_alabel_to_ulabel(const char *alabel)
{
#ifdef HAVE_LIBIDN
    int  ret;              /* just in case we might want to use it someday */
    char *buf;

    if (alabel == NULL)
        return 0;
    if ((ret = idna_to_unicode_8z8z(alabel, &buf, 0)) != IDNA_SUCCESS)  {
        return NULL;
    }
    return buf;
#else
    return NULL;
#endif
}


char *
getdns_display_ip_address(const struct getdns_bindata
    *bindata_of_ipv4_or_ipv6_address)
{
	char buff[256];
	if (!bindata_of_ipv4_or_ipv6_address ||
	    bindata_of_ipv4_or_ipv6_address->size == 0 ||
	    !bindata_of_ipv4_or_ipv6_address->data) {
		return NULL;
	}
	if (bindata_of_ipv4_or_ipv6_address->size == 4) {
		const char *ipStr = inet_ntop(AF_INET,
		    bindata_of_ipv4_or_ipv6_address->data,
		    buff,
		    256);
		if (ipStr) {
			return strdup(ipStr);
		}
	} else if (bindata_of_ipv4_or_ipv6_address->size == 16) {
		const char *ipStr = inet_ntop(AF_INET6,
		    bindata_of_ipv4_or_ipv6_address->data,
		    buff,
		    256);
		if (ipStr) {
			return strdup(ipStr);
		}
	}
	return NULL;
}

getdns_return_t
getdns_strerror(getdns_return_t err, char *buf, size_t buflen)
{
	const char *err_str = getdns_get_errorstr_by_id(err);

	(void) snprintf(buf, buflen, "%s",
	    err_str ? err_str : "/* <unknown getdns value> */");

	return GETDNS_RETURN_GOOD;
}				/* getdns_strerror */


/* --------------------- rr_dict, wire, str conversions --------------------- */


getdns_return_t
getdns_rr_dict2wire(
    const getdns_dict *rr_dict, uint8_t **wire, size_t *wire_sz)
{
	uint8_t buf_spc[4096], *buf;
	size_t buf_len = sizeof(buf_spc);
	getdns_return_t r = getdns_rr_dict2wire_buf(
	    rr_dict, buf_spc, &buf_len);

	if (r != GETDNS_RETURN_GOOD && r != GETDNS_RETURN_NEED_MORE_SPACE)
		return r;

	if (!(buf = malloc(buf_len ? buf_len : 1)))
		return GETDNS_RETURN_MEMORY_ERROR;

	if (!r)
		memcpy(buf, buf_spc, buf_len);

	else if ((r = getdns_rr_dict2wire_buf(rr_dict, buf, &buf_len))) {
		free(buf);
		return r;
	}
	*wire = buf;
	*wire_sz = buf_len;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_rr_dict2wire_buf(
    const getdns_dict *rr_dict, uint8_t *wire, size_t *wire_sz)
{
	int my_wire_sz;
	getdns_return_t r;

	if (!wire_sz)
		return GETDNS_RETURN_INVALID_PARAMETER;
	else
		my_wire_sz = *wire_sz;

	r = getdns_rr_dict2wire_scan(rr_dict, &wire, &my_wire_sz);
	if (r == GETDNS_RETURN_GOOD || r == GETDNS_RETURN_NEED_MORE_SPACE)
		*wire_sz -= my_wire_sz;
	return r;
}

getdns_return_t
getdns_rr_dict2wire_scan(
    const getdns_dict *rr_dict, uint8_t **wire, int *wire_sz)
{
	getdns_return_t r;
	gldns_buffer gbuf;

	if (!rr_dict || !wire || !*wire || !wire_sz)
		return GETDNS_RETURN_INVALID_PARAMETER;


	gldns_buffer_init_frm_data(&gbuf, *wire, *wire_sz);
	if ((r = _getdns_rr_dict2wire(rr_dict, &gbuf)))
		return r;

	if (gldns_buffer_position(&gbuf) == 0)
		return GETDNS_RETURN_GENERIC_ERROR;

	*wire += gldns_buffer_position(&gbuf);
	*wire_sz -= gldns_buffer_position(&gbuf);
	if (gldns_buffer_position(&gbuf) > gldns_buffer_limit(&gbuf))
		return GETDNS_RETURN_NEED_MORE_SPACE;
	else
		return GETDNS_RETURN_GOOD;
}

static struct mem_funcs _getdns_plain_mem_funcs = {
	MF_PLAIN, .mf.pln = { malloc, realloc, free }
};

getdns_return_t
_getdns_wire2rr_dict(struct mem_funcs *mf,
    const uint8_t *wire, size_t wire_len, getdns_dict **rr_dict)
{
	return _getdns_wire2rr_dict_scan(mf, &wire, &wire_len, rr_dict);
}
getdns_return_t
getdns_wire2rr_dict(
    const uint8_t *wire, size_t wire_len, getdns_dict **rr_dict)
{
	return _getdns_wire2rr_dict(
	    &_getdns_plain_mem_funcs, wire, wire_len, rr_dict);
}

getdns_return_t
_getdns_wire2rr_dict_buf(struct mem_funcs *mf,
    const uint8_t *wire, size_t *wire_len, getdns_dict **rr_dict)
{
	size_t my_wire_len;
	getdns_return_t r;

	if (!wire_len)
		return GETDNS_RETURN_INVALID_PARAMETER;
	else
		my_wire_len = *wire_len;

	if ((r = _getdns_wire2rr_dict_scan(mf, &wire, &my_wire_len, rr_dict)))
		return r;
	
	*wire_len -= my_wire_len;
	return GETDNS_RETURN_GOOD;
}
getdns_return_t
getdns_wire2rr_dict_buf(
    const uint8_t *wire, size_t *wire_len, getdns_dict **rr_dict)
{
	return _getdns_wire2rr_dict_buf(
	    &_getdns_plain_mem_funcs, wire, wire_len, rr_dict);
}

getdns_return_t
_getdns_wire2rr_dict_scan(struct mem_funcs *mf,
    const uint8_t **wire, size_t *wire_len, getdns_dict **rr_dict)
{
	_getdns_rr_iter rr_iter_spc, *rr_iter;

	if (!wire || !*wire || !wire_len || !rr_dict)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(rr_iter = _getdns_single_rr_iter_init(
	    &rr_iter_spc, *wire, *wire_len)))
		return GETDNS_RETURN_GENERIC_ERROR;

	if (!(*rr_dict = _getdns_rr_iter2rr_dict(mf, rr_iter)))
		return GETDNS_RETURN_MEMORY_ERROR;

	*wire_len -= (rr_iter->nxt - rr_iter->pos);
	*wire = rr_iter->nxt;

	return GETDNS_RETURN_GOOD;
}
getdns_return_t
getdns_wire2rr_dict_scan(
    const uint8_t **wire, size_t *wire_len, getdns_dict **rr_dict)
{
	return _getdns_wire2rr_dict_scan(
	    &_getdns_plain_mem_funcs, wire, wire_len, rr_dict);
}


getdns_return_t
getdns_rr_dict2str(
    const getdns_dict *rr_dict, char **str)
{
	char buf_spc[4096], *buf;
	size_t buf_len = sizeof(buf_spc) - 1;
	getdns_return_t r = getdns_rr_dict2str_buf(
	    rr_dict, buf_spc, &buf_len);

	if (r != GETDNS_RETURN_GOOD && r != GETDNS_RETURN_NEED_MORE_SPACE)
		return r;
	
	buf_len += 1;
	if (!(buf = malloc(buf_len)))
		return GETDNS_RETURN_MEMORY_ERROR;

	if (!r)
		memcpy(buf, buf_spc, buf_len);

	else if ((r = getdns_rr_dict2str_buf(rr_dict, buf, &buf_len))) {
		free(buf);
		return r;
	}
	*str = buf;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_rr_dict2str_buf(
    const getdns_dict *rr_dict, char *str, size_t *str_len)
{
	int my_str_len;
	getdns_return_t r;

	if (!str_len)
		return GETDNS_RETURN_INVALID_PARAMETER;
	else
		my_str_len = *str_len;

	r = getdns_rr_dict2str_scan(rr_dict, &str, &my_str_len);
	if (r == GETDNS_RETURN_GOOD || r == GETDNS_RETURN_NEED_MORE_SPACE)
		*str_len -= my_str_len;
	return r;

}

getdns_return_t
getdns_rr_dict2str_scan(
    const getdns_dict *rr_dict, char **str, int *str_len)
{
	getdns_return_t r;
	gldns_buffer gbuf;
	uint8_t buf_spc[4096], *buf = buf_spc, *scan_buf;
	size_t sz, scan_sz;
	int prev_str_len;
	char *prev_str;
	int sz_needed;

	if (!rr_dict || !str || !*str || !str_len)
		return GETDNS_RETURN_INVALID_PARAMETER;

	gldns_buffer_init_frm_data(&gbuf, buf, sizeof(buf_spc));
	r = _getdns_rr_dict2wire(rr_dict, &gbuf);
	if (gldns_buffer_position(&gbuf) > sizeof(buf_spc)) {
		if (!(buf = GETDNS_XMALLOC(
		    rr_dict->mf, uint8_t, (sz = gldns_buffer_position(&gbuf))))) {
			return GETDNS_RETURN_MEMORY_ERROR;
		}
		gldns_buffer_init_frm_data(&gbuf, buf, sz);
		r = _getdns_rr_dict2wire(rr_dict, &gbuf);
	}
	if (r) {
		if (buf != buf_spc)
			GETDNS_FREE(rr_dict->mf, buf);
		return r;
	}
	scan_buf = gldns_buffer_begin(&gbuf);
	scan_sz  = gldns_buffer_position(&gbuf);
	prev_str = *str;
	prev_str_len = *str_len;
	sz = (size_t)*str_len;
	sz_needed = gldns_wire2str_rr_scan(
	    &scan_buf, &scan_sz, str, &sz, NULL, 0);

	if (sz_needed > prev_str_len) {
		*str = prev_str + sz_needed;
		*str_len = prev_str_len - sz_needed;
		r = GETDNS_RETURN_NEED_MORE_SPACE;
	} else  {
		*str_len = sz;
		**str = 0;
	}
	if (buf != buf_spc)
		GETDNS_FREE(rr_dict->mf, buf);
	return r;
}


getdns_return_t
_getdns_str2rr_dict(struct mem_funcs *mf,
    const char *str, getdns_dict **rr_dict, const char *origin, uint32_t default_ttl)
{
	uint8_t wire_spc[4096], *wire = wire_spc;
	uint8_t origin_spc[256], *origin_wf;
	size_t origin_len = sizeof(origin_spc), wire_len = sizeof(wire_spc);
	int e;
	getdns_return_t r;

	if (!str || !rr_dict)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!origin)
		origin_wf = NULL;

	else if (gldns_str2wire_dname_buf(origin, origin_spc, &origin_len))
		return GETDNS_RETURN_GENERIC_ERROR;
	else
		origin_wf = origin_spc;

	e = gldns_str2wire_rr_buf(str, wire, &wire_len,
	    NULL, default_ttl, origin_wf, origin_len, NULL, 0);
	if (GLDNS_WIREPARSE_ERROR(e) == GLDNS_WIREPARSE_ERR_BUFFER_TOO_SMALL) {

		if (!(wire = GETDNS_XMALLOC(
		    *mf, uint8_t, (wire_len = GLDNS_RR_BUF_SIZE))))
			return GETDNS_RETURN_MEMORY_ERROR;
		e = gldns_str2wire_rr_buf(str, wire, &wire_len,
	            NULL, default_ttl, origin_wf, origin_len, NULL, 0);
	}
	if (e) {
		if (wire != wire_spc)
			GETDNS_FREE(*mf, wire);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	r = _getdns_wire2rr_dict(mf, wire, wire_len, rr_dict);
	if (wire != wire_spc)
		GETDNS_FREE(*mf, wire);
	return r;
}
getdns_return_t
getdns_str2rr_dict(
    const char *str, getdns_dict **rr_dict, const char *origin, uint32_t default_ttl)
{
	return _getdns_str2rr_dict(
	    &_getdns_plain_mem_funcs, str, rr_dict, origin, default_ttl);
}


getdns_return_t
_getdns_fp2rr_list(struct mem_funcs *mf,
    FILE *in, getdns_list **rr_list, const char *origin, uint32_t default_ttl)
{
	struct gldns_file_parse_state pst;
	getdns_list *rrs;
	getdns_return_t r = GETDNS_RETURN_GOOD;
	uint8_t *rr;
	size_t len, dname_len;
	getdns_dict *rr_dict;

	if (!in || !rr_list)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!origin) {
		*pst.origin = 0;
		pst.origin_len = 1;

	} else if (gldns_str2wire_dname_buf(origin,pst.origin,&pst.origin_len))
		return GETDNS_RETURN_GENERIC_ERROR;

	*pst.prev_rr = 0;
	pst.prev_rr_len = 1;
	pst.default_ttl = default_ttl;
	pst.lineno = 1;

	if (!(rrs = _getdns_list_create_with_mf(mf)))
		return GETDNS_RETURN_MEMORY_ERROR;
	

	if (!(rr = GETDNS_XMALLOC(*mf, uint8_t, GLDNS_RR_BUF_SIZE)))
		r = GETDNS_RETURN_MEMORY_ERROR;

	else while (r == GETDNS_RETURN_GOOD && !feof(in)) {
		len = GLDNS_RR_BUF_SIZE;
		dname_len = 0;
		if (gldns_fp2wire_rr_buf(in, rr, &len, &dname_len, &pst))
			break;
		if (dname_len && dname_len < sizeof(pst.prev_rr)) {
			memcpy(pst.prev_rr, rr, dname_len);
			pst.prev_rr_len = dname_len;
		}
		if (len == 0)
			continue;
		if ((r = _getdns_wire2rr_dict(mf, rr, len, &rr_dict)))
			break;
		if ((r = _getdns_list_append_this_dict(rrs, rr_dict)))
			getdns_dict_destroy(rr_dict);
	}
	if (rr)
		GETDNS_FREE(*mf, rr);
	if (r)
		getdns_list_destroy(rrs);
	else
		*rr_list = rrs;
	return r;
}

getdns_return_t
getdns_fp2rr_list(
    FILE *in, getdns_list **rr_list, const char *origin, uint32_t default_ttl)
{
	return _getdns_fp2rr_list(
	    &_getdns_plain_mem_funcs, in, rr_list, origin, default_ttl);
}

#define SET_WIRE_INT(X,Y) if (getdns_dict_set_int(header, #X , (int) \
                              GLDNS_ ## Y ## _WIRE(*wire))) goto error
#define SET_WIRE_BIT(X,Y) if (getdns_dict_set_int(header, #X , \
                              GLDNS_ ## Y ## _WIRE(*wire) ? 1 : 0)) goto error
#define SET_WIRE_CNT(X,Y) if (getdns_dict_set_int(header, #X , (int) \
                              GLDNS_ ## Y (*wire))) goto error 

getdns_return_t
_getdns_wire2msg_dict_scan(struct mem_funcs *mf,
    const uint8_t **wire, size_t *wire_len, getdns_dict **msg_dict)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	getdns_dict *result = NULL, *header = NULL, *rr_dict = NULL;
	_getdns_rr_iter rr_iter_storage, *rr_iter;
	_getdns_section section;
	getdns_list *sections[16] = { NULL, NULL, NULL, NULL
	                            , NULL, NULL, NULL, NULL
	                            , NULL, NULL, NULL, NULL
	                            , NULL, NULL, NULL, NULL };
	const uint8_t *eop; /* end of packet */

	if (!wire || !*wire || !wire_len || !msg_dict)
		return GETDNS_RETURN_INVALID_PARAMETER;

       	if (!(result = _getdns_dict_create_with_mf(mf)) ||
	    !(header = _getdns_dict_create_with_mf(mf)) ||
	    !(sections[SECTION_ANSWER]
	             = _getdns_list_create_with_mf(mf)) ||
	    !(sections[SECTION_AUTHORITY]
	             = _getdns_list_create_with_mf(mf)) ||
	    !(sections[SECTION_ADDITIONAL]
	             = _getdns_list_create_with_mf(mf))) {
		r = GETDNS_RETURN_MEMORY_ERROR;
		goto error;
	}
	SET_WIRE_INT(id, ID);
	SET_WIRE_BIT(qr, QR);
	SET_WIRE_BIT(aa, AA);
	SET_WIRE_BIT(tc, TC);
	SET_WIRE_BIT(rd, RD);
	SET_WIRE_BIT(cd, CD);
	SET_WIRE_BIT(ra, RA);
	SET_WIRE_BIT(ad, AD);
	SET_WIRE_INT(opcode, OPCODE);
	SET_WIRE_INT(rcode, RCODE);
	SET_WIRE_BIT(z, Z);

	SET_WIRE_CNT(qdcount, QDCOUNT);
	SET_WIRE_CNT(ancount, ANCOUNT);
	SET_WIRE_CNT(nscount, NSCOUNT);
	SET_WIRE_CNT(arcount, ARCOUNT);

	/* header */
    	if ((r = _getdns_dict_set_this_dict(result, "header", header)))
		goto error;
	header = NULL;
	eop = *wire + 12;

	for ( rr_iter = _getdns_rr_iter_init(&rr_iter_storage,*wire,*wire_len)
	    ; rr_iter
	    ; rr_iter = _getdns_rr_iter_next(rr_iter)) {

		if (rr_iter->nxt > eop)
			eop = rr_iter->nxt;

		if (!(rr_dict = _getdns_rr_iter2rr_dict(mf, rr_iter)))
			continue;

		switch ((section = _getdns_rr_iter_section(rr_iter))) {
		case SECTION_QUESTION:
			if ((r = _getdns_dict_set_this_dict(
			     result, "question", rr_dict)))
				goto error;
			break;
		case SECTION_ANSWER:
		case SECTION_AUTHORITY:
		case SECTION_ADDITIONAL:
			if ((r = _getdns_list_append_this_dict(
			     sections[section], rr_dict)))
				goto error;
			break;
		default:
			r = GETDNS_RETURN_GENERIC_ERROR;
			goto error;
		}
		rr_dict = NULL;
	}
	if (!(r = _getdns_dict_set_this_list(result, "answer",
	    sections[SECTION_ANSWER])))
		sections[SECTION_ANSWER] = NULL;
	else	goto error;

	if (!(r = _getdns_dict_set_this_list(result, "authority",
	    sections[SECTION_AUTHORITY])))
		sections[SECTION_AUTHORITY] = NULL;
	else	goto error;

	if (!(r = _getdns_dict_set_this_list(result, "additional",
	    sections[SECTION_ADDITIONAL])))
		sections[SECTION_ADDITIONAL] = NULL;
	else	goto error;

	*wire_len -= (eop - *wire);
	*wire = eop;
error:
	getdns_dict_destroy(rr_dict);
	getdns_list_destroy(sections[SECTION_ADDITIONAL]);
	getdns_list_destroy(sections[SECTION_AUTHORITY]);
	getdns_list_destroy(sections[SECTION_ANSWER]);
	getdns_dict_destroy(header);
	if (r)
		getdns_dict_destroy(result);
	else
		*msg_dict = result;

	return r;
}


getdns_return_t
_getdns_wire2msg_dict(struct mem_funcs *mf,
    const uint8_t *wire, size_t wire_len, getdns_dict **msg_dict)
{
	return _getdns_wire2msg_dict_scan(mf, &wire, &wire_len, msg_dict);
}
getdns_return_t
getdns_wire2msg_dict(
    const uint8_t *wire, size_t wire_len, getdns_dict **msg_dict)
{
	return _getdns_wire2msg_dict(
	    &_getdns_plain_mem_funcs, wire, wire_len, msg_dict);
}

getdns_return_t
_getdns_wire2msg_dict_buf(struct mem_funcs *mf,
    const uint8_t *wire, size_t *wire_len, getdns_dict **msg_dict)
{
	size_t my_wire_len;
	getdns_return_t r;

	if (!wire_len)
		return GETDNS_RETURN_INVALID_PARAMETER;
	else
		my_wire_len = *wire_len;

	if ((r = _getdns_wire2msg_dict_scan(mf, &wire, &my_wire_len, msg_dict)))
		return r;
	
	*wire_len -= my_wire_len;
	return GETDNS_RETURN_GOOD;
}
getdns_return_t
getdns_wire2msg_dict_buf(
    const uint8_t *wire, size_t *wire_len, getdns_dict **msg_dict)
{
	return _getdns_wire2msg_dict_buf(
	    &_getdns_plain_mem_funcs, wire, wire_len, msg_dict);
}

getdns_return_t
getdns_wire2msg_dict_scan(
    const uint8_t **wire, size_t *wire_len, getdns_dict **msg_dict)
{
	return _getdns_wire2msg_dict_scan(
	    &_getdns_plain_mem_funcs, wire, wire_len, msg_dict);
}

#define SET_HEADER_INT(X,Y) \
	if (!getdns_dict_get_int(reply, "/header/" #X, &n)) \
		GLDNS_ ## Y ## _SET(header, n);
#define SET_HEADER_BIT(X,Y) \
	if (!getdns_dict_get_int(reply, "/header/" #X, &n)) { \
		if (n) GLDNS_ ## Y ## _SET(header); \
		else   GLDNS_ ## Y ## _CLR(header); \
	}

getdns_return_t
_getdns_reply_dict2wire(
    const getdns_dict *reply, gldns_buffer *buf, int reuse_header)
{
	uint8_t header_spc[GLDNS_HEADER_SIZE], *header;
	uint32_t n, qtype, qclass = GETDNS_RRCLASS_IN;
	size_t pkt_start, i;
	getdns_list *section;
	getdns_dict *rr_dict;
	getdns_bindata *qname;

	pkt_start = gldns_buffer_position(buf);
	if (reuse_header) {
		if (gldns_buffer_remaining(buf) < GLDNS_HEADER_SIZE)
			return GETDNS_RETURN_NEED_MORE_SPACE;
		header = gldns_buffer_current(buf);
		gldns_buffer_skip(buf, GLDNS_HEADER_SIZE);
	} else
		(void) memset((header = header_spc), 0, GLDNS_HEADER_SIZE);

	SET_HEADER_INT(id, ID);
	SET_HEADER_BIT(qr, QR);
	SET_HEADER_BIT(aa, AA);
	SET_HEADER_BIT(tc, TC);
	SET_HEADER_BIT(rd, RD);
	SET_HEADER_BIT(cd, CD);
	SET_HEADER_BIT(ra, RA);
	SET_HEADER_BIT(ad, AD);
	SET_HEADER_INT(opcode, OPCODE);
	SET_HEADER_INT(rcode, RCODE);
	SET_HEADER_BIT(z, Z);

	if (!reuse_header)
		gldns_buffer_write(buf, header, GLDNS_HEADER_SIZE);

	if (!getdns_dict_get_bindata(reply, "/question/qname", &qname) &&
	    !getdns_dict_get_int(reply, "/question/qtype", &qtype)) {
		(void)getdns_dict_get_int(reply, "/question/qclass", &qclass);
		gldns_buffer_write(buf, qname->data, qname->size);
		gldns_buffer_write_u16(buf, (uint16_t)qtype);
		gldns_buffer_write_u16(buf, (uint16_t)qclass);
		gldns_buffer_write_u16_at(buf, pkt_start+GLDNS_QDCOUNT_OFF, 1);
		if (reuse_header) {
			gldns_buffer_write_u16_at(
			    buf, pkt_start+GLDNS_ANCOUNT_OFF, 0);
			gldns_buffer_write_u16_at(
			    buf, pkt_start+GLDNS_NSCOUNT_OFF, 0);
			gldns_buffer_write_u16_at(
			    buf, pkt_start+GLDNS_ARCOUNT_OFF, 0);
		}
	}
	if (!getdns_dict_get_list(reply, "answer", &section)) {
		for ( n = 0, i = 0
		    ; !getdns_list_get_dict(section, i, &rr_dict); i++) {

			 if (!_getdns_rr_dict2wire(rr_dict, buf))
				 n++;
		}
		gldns_buffer_write_u16_at(buf, pkt_start+GLDNS_ANCOUNT_OFF, n);
	}
	if (!getdns_dict_get_list(reply, "authority", &section)) {
		for ( n = 0, i = 0
		    ; !getdns_list_get_dict(section, i, &rr_dict); i++) {

			 if (!_getdns_rr_dict2wire(rr_dict, buf))
				 n++;
		}
		gldns_buffer_write_u16_at(buf, pkt_start+GLDNS_NSCOUNT_OFF, n);
	}
	if (!getdns_dict_get_list(reply, "additional", &section)) {
		for ( n = 0, i = 0
		    ; !getdns_list_get_dict(section, i, &rr_dict); i++) {

			 if (!_getdns_rr_dict2wire(rr_dict, buf))
				 n++;
		}
		gldns_buffer_write_u16_at(buf, pkt_start+GLDNS_ARCOUNT_OFF, n);
	}
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_msg_dict2wire_buf(const getdns_dict *msg_dict, gldns_buffer *gbuf)
{
	getdns_return_t r;
	getdns_list *replies;
	getdns_dict *reply;
	size_t i;

	if ((r = getdns_dict_get_list(msg_dict, "replies_tree", &replies))) {
		if (r != GETDNS_RETURN_NO_SUCH_DICT_NAME)
			return r;
		return _getdns_reply_dict2wire(msg_dict, gbuf, 0);
	}
	for (i = 0; r == GETDNS_RETURN_GOOD; i++) {
		if (!(r = getdns_list_get_dict(replies, i, &reply)))
			r = _getdns_reply_dict2wire(reply, gbuf, 0);
	}
	return r == GETDNS_RETURN_NO_SUCH_LIST_ITEM ? GETDNS_RETURN_GOOD : r;
}

getdns_return_t
getdns_msg_dict2wire(
    const getdns_dict *msg_dict, uint8_t **wire, size_t *wire_sz)
{
	uint8_t buf_spc[4096], *buf;
	size_t buf_len = sizeof(buf_spc);
	getdns_return_t r = getdns_msg_dict2wire_buf(
	    msg_dict, buf_spc, &buf_len);

	if (r != GETDNS_RETURN_GOOD && r != GETDNS_RETURN_NEED_MORE_SPACE)
		return r;

	if (!(buf = malloc(buf_len ? buf_len : 1)))
		return GETDNS_RETURN_MEMORY_ERROR;

	if (!r)
		memcpy(buf, buf_spc, buf_len);

	else if ((r = getdns_msg_dict2wire_buf(msg_dict, buf, &buf_len))) {
		free(buf);
		return r;
	}
	*wire = buf;
	*wire_sz = buf_len;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_msg_dict2wire_buf(
    const getdns_dict *msg_dict, uint8_t *wire, size_t *wire_sz)
{
	int my_wire_sz;
	getdns_return_t r;

	if (!wire_sz)
		return GETDNS_RETURN_INVALID_PARAMETER;
	else
		my_wire_sz = *wire_sz;

	r = getdns_msg_dict2wire_scan(msg_dict, &wire, &my_wire_sz);
	if (r == GETDNS_RETURN_GOOD || r == GETDNS_RETURN_NEED_MORE_SPACE)
		*wire_sz -= my_wire_sz;
	return r;
}

getdns_return_t
getdns_msg_dict2wire_scan(
    const getdns_dict *msg_dict, uint8_t **wire, int *wire_sz)
{
	getdns_return_t r;
	gldns_buffer gbuf;

	if (!msg_dict || !wire || !wire_sz || (!*wire && *wire_sz))
		return GETDNS_RETURN_INVALID_PARAMETER;

	gldns_buffer_init_frm_data(&gbuf, *wire, *wire_sz);
	if ((r = _getdns_msg_dict2wire_buf(msg_dict, &gbuf)))
		return r;

	if (gldns_buffer_position(&gbuf) == 0)
		return GETDNS_RETURN_GENERIC_ERROR;

	*wire += gldns_buffer_position(&gbuf);
	*wire_sz -= gldns_buffer_position(&gbuf);
	if (gldns_buffer_position(&gbuf) > gldns_buffer_limit(&gbuf))
		return GETDNS_RETURN_NEED_MORE_SPACE;
	else
		return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_msg_dict2str(
    const getdns_dict *msg_dict, char **str)
{
	char buf_spc[4096], *buf;
	size_t buf_len = sizeof(buf_spc) - 1;
	getdns_return_t r = getdns_msg_dict2str_buf(
	    msg_dict, buf_spc, &buf_len);

	if (r != GETDNS_RETURN_GOOD && r != GETDNS_RETURN_NEED_MORE_SPACE)
		return r;
	
	buf_len += 1;
	if (!(buf = malloc(buf_len)))
		return GETDNS_RETURN_MEMORY_ERROR;

	if (!r)
		memcpy(buf, buf_spc, buf_len);

	else if ((r = getdns_msg_dict2str_buf(msg_dict, buf, &buf_len))) {
		free(buf);
		return r;
	}
	*str = buf;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_msg_dict2str_buf(
    const getdns_dict *msg_dict, char *str, size_t *str_len)
{
	int my_str_len;
	getdns_return_t r;

	if (!str_len)
		return GETDNS_RETURN_INVALID_PARAMETER;
	else
		my_str_len = *str_len;

	r = getdns_msg_dict2str_scan(msg_dict, &str, &my_str_len);
	if (r == GETDNS_RETURN_GOOD || r == GETDNS_RETURN_NEED_MORE_SPACE)
		*str_len -= my_str_len;
	return r;

}

getdns_return_t
getdns_msg_dict2str_scan(
    const getdns_dict *msg_dict, char **str, int *str_len)
{
	getdns_return_t r;
	gldns_buffer gbuf;
	uint8_t buf_spc[4096], *buf = buf_spc, *scan_buf;
	size_t sz, scan_sz;
	int prev_str_len;
	char *prev_str;
	int sz_needed;

	if (!msg_dict || !str || !*str || !str_len)
		return GETDNS_RETURN_INVALID_PARAMETER;

	gldns_buffer_init_frm_data(&gbuf, buf, sizeof(buf_spc));
	r = _getdns_msg_dict2wire_buf(msg_dict, &gbuf);
	if (gldns_buffer_position(&gbuf) > sizeof(buf_spc)) {
		if (!(buf = GETDNS_XMALLOC(
		    msg_dict->mf, uint8_t, (sz = gldns_buffer_position(&gbuf))))) {
			return GETDNS_RETURN_MEMORY_ERROR;
		}
		gldns_buffer_init_frm_data(&gbuf, buf, sz);
		r = _getdns_msg_dict2wire_buf(msg_dict, &gbuf);
	}
	if (r) {
		if (buf != buf_spc)
			GETDNS_FREE(msg_dict->mf, buf);
		return r;
	}
	scan_buf = gldns_buffer_begin(&gbuf);
	scan_sz  = gldns_buffer_position(&gbuf);
	prev_str = *str;
	prev_str_len = *str_len;
	sz = (size_t)*str_len;
	sz_needed = gldns_wire2str_pkt_scan(
	    &scan_buf, &scan_sz, str, &sz);

	if (sz_needed > prev_str_len) {
		*str = prev_str + sz_needed;
		*str_len = prev_str_len - sz_needed;
		r = GETDNS_RETURN_NEED_MORE_SPACE;
	} else  {
		*str_len = sz;
		**str = 0;
	}
	if (buf != buf_spc)
		GETDNS_FREE(msg_dict->mf, buf);
	return r;
}


/* convert.c */
