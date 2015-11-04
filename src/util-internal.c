/**
 *
 * \file util-internal.c
 * @brief private library routines
 *
 * These routines are not intended to be used by applications calling into
 * the library.
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

#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include "config.h"
#include "getdns/getdns.h"
#include "dict.h"
#include "list.h"
#include "util-internal.h"
#include "types-internal.h"
#include "rr-dict.h"
#if defined(WIRE_DEBUG) && WIRE_DEBUG
#include "gldns/wire2str.h"
#endif
#include "gldns/str2wire.h"
#include "gldns/gbuffer.h"
#include "gldns/pkthdr.h"

/**
  * this is a comprehensive list of extensions and their data types
  * used by validate_extensions()
  * The list has to be in sorted order for bsearch lookup in function
  * validate_extensions.
  */
static getdns_extension_format extformats[] = {
	{"add_opt_parameters", t_dict},
	{"add_warning_for_bad_dns", t_int},
	{"dnssec_return_only_secure", t_int},
	{"dnssec_return_status", t_int},
	{"dnssec_return_validation_chain", t_int},
#ifdef DNSSEC_ROADBLOCK_AVOIDANCE
	{"dnssec_roadblock_avoidance", t_int},
#endif
#ifdef EDNS_COOKIES
	{"edns_cookies", t_int},
#endif
	{"return_api_information", t_int},
	{"return_both_v4_and_v6", t_int},
	{"return_call_debugging", t_int},
	{"specify_class", t_int},
};


getdns_return_t
getdns_dict_util_get_string(struct getdns_dict * dict, char *name, char **result)
{
	struct getdns_bindata *bindata = NULL;
	if (!result) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	*result = NULL;
	getdns_dict_get_bindata(dict, name, &bindata);
	if (!bindata) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	*result = (char *) bindata->data;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_dict_to_sockaddr(struct getdns_dict * ns, struct sockaddr_storage * output)
{
	char *address_type = NULL;
	struct getdns_bindata *address_data = NULL;
	uint32_t port = 53;
	memset(output, 0, sizeof(struct sockaddr_storage));
	output->ss_family = AF_UNSPEC;

	uint32_t prt = 0;
	if (getdns_dict_get_int(ns, GETDNS_STR_PORT,
		&prt) == GETDNS_RETURN_GOOD) {
		port = prt;
	}

	getdns_dict_util_get_string(ns, GETDNS_STR_ADDRESS_TYPE,
	    &address_type);
	getdns_dict_get_bindata(ns, GETDNS_STR_ADDRESS_DATA, &address_data);
	if (!address_type || !address_data) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	if (strncmp(GETDNS_STR_IPV4, address_type,
		strlen(GETDNS_STR_IPV4)) == 0) {
		/* data is an in_addr_t */
		struct sockaddr_in *addr = (struct sockaddr_in *) output;
		addr->sin_family = AF_INET;
		addr->sin_port = htons((uint16_t) port);
		memcpy(&(addr->sin_addr), address_data->data,
		    address_data->size);
	} else {
		/* data is a v6 addr in host order */
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *) output;
		addr->sin6_family = AF_INET6;
		addr->sin6_port = htons((uint16_t) port);
		memcpy(&(addr->sin6_addr), address_data->data,
		    address_data->size);
	}
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_sockaddr_to_dict(struct getdns_context *context, struct sockaddr_storage *address,
    struct getdns_dict ** output)
{
	if (!output || !address) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	struct getdns_bindata addr_data;
	*output = NULL;
	struct getdns_dict *result = getdns_dict_create_with_context(context);
	if (address->ss_family == AF_INET) {
		struct sockaddr_in *addr = (struct sockaddr_in *) address;
		getdns_dict_util_set_string(result, GETDNS_STR_ADDRESS_TYPE,
		    GETDNS_STR_IPV4);
		addr_data.size = sizeof(addr->sin_addr);
		addr_data.data = (uint8_t *) & (addr->sin_addr);
		getdns_dict_set_bindata(result, GETDNS_STR_ADDRESS_DATA,
		    &addr_data);
	} else if (address->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *) address;
		getdns_dict_util_set_string(result, GETDNS_STR_ADDRESS_TYPE,
		    GETDNS_STR_IPV6);
		addr_data.size = sizeof(addr->sin6_addr);
		addr_data.data = (uint8_t *) & (addr->sin6_addr);
		getdns_dict_set_bindata(result, GETDNS_STR_ADDRESS_DATA,
		    &addr_data);
	} else {
		// invalid
		getdns_dict_destroy(result);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	*output = result;
	return GETDNS_RETURN_GOOD;
}

getdns_dict *
_getdns_rr_iter2rr_dict(struct mem_funcs *mf, _getdns_rr_iter *i)
{
	getdns_dict *rr_dict, *rdata_dict;
	getdns_bindata bindata;
	uint32_t int_val = 0;
	getdns_data_type val_type;
	_getdns_rdf_iter rdf_storage, *rdf;
	getdns_list *repeat_list = NULL;
	getdns_dict *repeat_dict = NULL;
	uint8_t ff_bytes[256];
	uint16_t rr_type;

	assert(i);
	if (!(rr_dict = _getdns_dict_create_with_mf(mf)))
		return NULL;

	bindata.data = _getdns_owner_if_or_as_decompressed(
	    i, ff_bytes, &bindata.size);

	/* question */
	if (_getdns_rr_iter_section(i) == GLDNS_SECTION_QUESTION) {

		if (getdns_dict_set_int(rr_dict, "qtype",
		    (uint32_t) gldns_read_uint16(i->rr_type)) ||

		    getdns_dict_set_int(rr_dict, "qclass",
		    (uint32_t) gldns_read_uint16(i->rr_type + 2)) ||

		    getdns_dict_set_bindata(rr_dict, "qname", &bindata)) {

			goto error;
		}
		return rr_dict;
	}
	if (getdns_dict_set_int(rr_dict, "type",
	    (uint32_t)(rr_type = gldns_read_uint16(i->rr_type)))) {

		goto error;
	}
	if (rr_type == GETDNS_RRTYPE_OPT) {
		int_val = gldns_read_uint16(i->rr_type + 6);

		if (getdns_dict_set_int(rr_dict, "udp_payload_size",
		    (uint32_t) gldns_read_uint16(i->rr_type + 2)) ||

		    getdns_dict_set_int(rr_dict, "extended_rcode",
		    (uint32_t) *(i->rr_type + 4)) ||

		    getdns_dict_set_int(rr_dict, "version",
		    (uint32_t) *(i->rr_type + 5)) ||
		    
		    getdns_dict_set_int(rr_dict, "do",
		    (uint32_t) ((int_val & 0x8000) >> 15)) ||

		    getdns_dict_set_int(rr_dict, "z",
		    (uint32_t) (int_val & 0x7FF))) {

			goto error;
		}
	} else if (getdns_dict_set_int(rr_dict, "class",
	    (uint32_t) gldns_read_uint16(i->rr_type + 2)) ||

	    getdns_dict_set_int(rr_dict, "ttl",
	    (uint32_t) gldns_read_uint32(i->rr_type + 4)) ||

	    getdns_dict_set_bindata(rr_dict, "name", &bindata)) {

		goto error;
	}
	if (!(rdata_dict = _getdns_dict_create_with_mf(mf)))
		return NULL;

	if (i->rr_type + 10 <= i->nxt) {
		bindata.size = i->nxt - (i->rr_type + 10);
		bindata.data = i->rr_type + 10;
		if (getdns_dict_set_bindata(rdata_dict, "rdata_raw", &bindata))
			goto rdata_error;
	}
	for ( rdf = _getdns_rdf_iter_init(&rdf_storage, i)
	    ; rdf; rdf = _getdns_rdf_iter_next(rdf)) {
		if (rdf->rdd_pos->type & GETDNS_RDF_INTEGER) {
			val_type = t_int;
			switch (rdf->rdd_pos->type & GETDNS_RDF_FIXEDSZ) {
			case 1:	int_val = *rdf->pos;
				break;
			case 2:	int_val = gldns_read_uint16(rdf->pos);
				break; 
			case 4:	int_val = gldns_read_uint32(rdf->pos);
				break;
			default:
				goto rdata_error;
			}
		} else if (rdf->rdd_pos->type & GETDNS_RDF_DNAME) {
			val_type = t_bindata;

			bindata.data = _getdns_rdf_if_or_as_decompressed(
			    rdf, ff_bytes, &bindata.size);

		} else if (rdf->rdd_pos->type & GETDNS_RDF_BINDATA) {
			val_type = t_bindata;
			if (rdf->rdd_pos->type & GETDNS_RDF_FIXEDSZ) {
				bindata.size = rdf->rdd_pos->type
				             & GETDNS_RDF_FIXEDSZ;
				bindata.data = rdf->pos;

			} else switch(rdf->rdd_pos->type & GETDNS_RDF_LEN_VAL){
			case 0x100:
				bindata.size = *rdf->pos;
				bindata.data = rdf->pos + 1;
				break;
			case 0x200:
				bindata.size = gldns_read_uint16(rdf->pos);
				bindata.data = rdf->pos + 2;
				break;
			default:
				bindata.size = rdf->nxt - rdf->pos;
				bindata.data = rdf->pos;
				break;
			}
		} else if (rdf->rdd_pos->type == GETDNS_RDF_SPECIAL)
			/* Abuse t_dict for special values */
			val_type = t_dict;
		else
			assert(0);

		if (! rdf->rdd_repeat) {
			switch (val_type) {
			case t_int:
				if (getdns_dict_set_int(rdata_dict,
				    rdf->rdd_pos->name, int_val))
					goto rdata_error;
				break;
			case t_bindata:
				if (getdns_dict_set_bindata(rdata_dict,
				    rdf->rdd_pos->name, &bindata))
					goto rdata_error;
				break;
			case t_dict:
				if (rdf->rdd_pos->special->dict_set_value(
				    rdata_dict, rdf->pos))
					goto rdata_error;
			default:
				break;
			}
			continue;
		}
		if (rdf->rdd_pos == rdf->rdd_repeat) {
			/* list with rdf values */

			if (! repeat_list && !(repeat_list =
			    _getdns_list_create_with_mf(mf)))

				goto rdata_error;
			
			switch (val_type) {
			case t_int:
				if (_getdns_list_append_int(repeat_list,
				    int_val))
					goto rdata_error;
				break;
			case t_bindata:
				if (_getdns_list_append_bindata(repeat_list,
				    &bindata))
					goto rdata_error;
				break;
			case t_dict:
				if (rdf->rdd_pos->special->list_append_value(
				    repeat_list, rdf->pos))
					goto rdata_error;
			default:
				break;
			}
			continue;
		}
		if (rdf->rdd_pos == rdf->rdd_repeat + 1) {

			if (repeat_dict) {
				if (! repeat_list && !(repeat_list =
				    _getdns_list_create_with_mf(mf)))
					goto rdata_error;
	
				if (_getdns_list_append_dict(
				    repeat_list, repeat_dict))
					goto rdata_error;

				getdns_dict_destroy(repeat_dict);
				repeat_dict = NULL;
			}
			if (!(repeat_dict =
			    _getdns_dict_create_with_mf(mf)))
				goto rdata_error;
		}
		assert(repeat_dict);
		switch (val_type) {
		case t_int:
			if (getdns_dict_set_int(repeat_dict,
			    rdf->rdd_pos->name, int_val))
				goto rdata_error;
			break;
		case t_bindata:
			if (getdns_dict_set_bindata(repeat_dict,
			    rdf->rdd_pos->name, &bindata))
				goto rdata_error;
			break;
		case t_dict:
			if (rdf->rdd_pos->special->dict_set_value(
			    repeat_dict, rdf->pos))
				goto rdata_error;
		default:
			break;
		}
	}
	if (repeat_dict) {
		if (!repeat_list && !(repeat_list =
		    _getdns_list_create_with_mf(mf)))
			goto rdata_error;
		if (_getdns_list_append_dict(repeat_list, repeat_dict))
			goto rdata_error;
		getdns_dict_destroy(repeat_dict);
		repeat_dict = NULL;
	}
	if (repeat_list) {
		if (getdns_dict_set_list(rdata_dict,
		    rdf_storage.rdd_repeat->name, repeat_list))
			goto rdata_error;
		getdns_list_destroy(repeat_list);
		repeat_list = NULL;
	}
	if (getdns_dict_set_dict(rr_dict, "rdata", rdata_dict))
		goto rdata_error;

	getdns_dict_destroy(rdata_dict);
	return rr_dict;

rdata_error:
	getdns_list_destroy(repeat_list);
	getdns_dict_destroy(repeat_dict);
	getdns_dict_destroy(rdata_dict);
error:
	getdns_dict_destroy(rr_dict);
	return NULL;
}

int
_getdns_dname_equal(const uint8_t *s1, const uint8_t *s2)
{
	uint8_t i;
	for (;;) {
		if (*s1 != *s2)
			return 0;
		else if (!*s1)
			return 1;
		for (i = *s1++, s2++; i > 0; i--, s1++, s2++)
			if (*s1 != *s2 && tolower((unsigned char)*s1)
			               != tolower((unsigned char)*s2))
				return 0;
	}
}

inline static getdns_dict *
set_dict(getdns_dict **var, getdns_dict *value)
{
	if (*var)
		getdns_dict_destroy(*var);
	return *var = value;
}

#define SET_WIRE_INT(X,Y) if (getdns_dict_set_int(header, #X , (int) \
                              GLDNS_ ## Y ## _WIRE(req->response))) goto error
#define SET_WIRE_BIT(X,Y) if (getdns_dict_set_int(header, #X , \
                              GLDNS_ ## Y ## _WIRE(req->response) ? 1 : 0)) goto error
#define SET_WIRE_CNT(X,Y) if (getdns_dict_set_int(header, #X , (int) \
                              GLDNS_ ## Y (req->response))) goto error 

getdns_dict *
_getdns_create_reply_dict(getdns_context *context, getdns_network_req *req,
    getdns_list *just_addrs, int *rrsigs_in_answer)
{
	/* turn a packet into this glorious structure
	 *
	 * {     # This is the first reply
	 * "header": { "id": 23456, "qr": 1, "opcode": 0, ... },
	 * "question": { "qname": <bindata for "www.example.com">, "qtype": 1, "qclass": 1 },
	 * "answer":
	 * [
	 * {
	 * "name": <bindata for "www.example.com">,
	 * "type": 1,
	 * "class": 1,
	 * "ttl": 33000,
	 * "rdata":
	 * {
	 * "ipv4_address": <bindata of 0x0a0b0c01>
	 * "rdata_raw": <bindata of 0x0a0b0c01>
	 * }
	 * }
	 * ],
	 * "authority":
	 * [
	 * {
	 * "name": <bindata for "ns1.example.com">,
	 * "type": 1,
	 * "class": 1,
	 * "ttl": 600,
	 * "rdata":
	 * {
	 * "ipv4_address": <bindata of 0x65439876>
	 * "rdata_raw": <bindata of 0x65439876>
	 * }
	 * }
	 * ]
	 * "additional": [],
	 * "canonical_name": <bindata for "www.example.com">,
	 * "answer_type": GETDNS_NAMETYPE_DNS
	 * }
	 *
	 */
	getdns_return_t r = GETDNS_RETURN_GOOD;
	getdns_dict *result = getdns_dict_create_with_context(context);
	getdns_dict *question = NULL;
	getdns_list *sections[4] = { NULL
	                           , getdns_list_create_with_context(context)
	                           , getdns_list_create_with_context(context)
	                           , getdns_list_create_with_context(context)
	                           };
	getdns_dict *rr_dict = NULL;
	_getdns_rr_iter rr_iter_storage, *rr_iter;
	_getdns_rdf_iter rdf_iter_storage, *rdf_iter;
	getdns_bindata bindata;
	gldns_pkt_section section;
	uint8_t canonical_name_space[256],
	       *canonical_name = canonical_name_space;
	uint8_t owner_name_space[256], *owner_name;
	size_t canonical_name_len = sizeof(canonical_name_space),
	       owner_name_len = sizeof(owner_name_space);
	int new_canonical = 0;
	uint16_t rr_type;
	getdns_dict *header = NULL;

	if (!result)
		goto error;

	if (!(header = getdns_dict_create_with_context(context)))
		goto error;

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
    	if ((r = getdns_dict_set_dict(result, "header", header)))
		goto error;

	canonical_name = req->owner->name;
	canonical_name_len = req->owner->name_len;

	for ( rr_iter = _getdns_rr_iter_init(&rr_iter_storage
	                                        , req->response
	                                        , req->response_len)
	    ; rr_iter
	    ; rr_iter = _getdns_rr_iter_next(rr_iter)) {

		if (!set_dict(&rr_dict,
		    _getdns_rr_iter2rr_dict(&context->mf, rr_iter)))
			continue;

		section = _getdns_rr_iter_section(rr_iter);
		if (section == GLDNS_SECTION_QUESTION) {

			if (getdns_dict_set_dict(result, "question", rr_dict))
				goto error;

			continue;
		}
		if (_getdns_list_append_dict(sections[section], rr_dict))
			goto error;


		rr_type = gldns_read_uint16(rr_iter->rr_type);
		if (section > GLDNS_SECTION_QUESTION &&
		    rr_type == GETDNS_RRTYPE_RRSIG && rrsigs_in_answer)
			*rrsigs_in_answer = 1;

		if (section != GLDNS_SECTION_ANSWER)
			continue;

		if (rr_type == GETDNS_RRTYPE_CNAME) {

			owner_name = _getdns_owner_if_or_as_decompressed(
			    rr_iter, owner_name_space, &owner_name_len);
			if (!_getdns_dname_equal(canonical_name, owner_name))
				continue;

			if (!(rdf_iter = _getdns_rdf_iter_init(
			     &rdf_iter_storage, rr_iter)))
				continue;

			new_canonical = 1;
			canonical_name = _getdns_rdf_if_or_as_decompressed(
			    rdf_iter,canonical_name_space,&canonical_name_len);
			continue;
		}

		if (rr_type != GETDNS_RRTYPE_A && rr_type != GETDNS_RRTYPE_AAAA)
			continue;

		if (!(rdf_iter = _getdns_rdf_iter_init(
		     &rdf_iter_storage, rr_iter)))
			continue;

		bindata.size = rdf_iter->nxt - rdf_iter->pos;
		bindata.data = rdf_iter->pos;
		if (!set_dict(&rr_dict, getdns_dict_create_with_context(context)) ||

		    getdns_dict_util_set_string(rr_dict, "address_type",
			    rr_type == GETDNS_RRTYPE_A ? "IPv4" : "IPv6" ) ||

		    getdns_dict_set_bindata(rr_dict,"address_data",&bindata) ||

		    (just_addrs && _getdns_list_append_dict(just_addrs, rr_dict))) {

			goto error;
		}
	}
	if (getdns_dict_set_list(result, "answer",
	    sections[GLDNS_SECTION_ANSWER]) ||

	    getdns_dict_set_list(result, "authority",
	    sections[GLDNS_SECTION_AUTHORITY]) ||

	    getdns_dict_set_list(result, "additional",
	    sections[GLDNS_SECTION_ADDITIONAL])) {

		goto error;
	}

	/* other stuff
	 * Note that spec doesn't explicitely mention these.
	 * They are only showcased in the response dict example */
	if (getdns_dict_set_int(result, "answer_type", GETDNS_NAMETYPE_DNS))
		goto error;
	
	while (new_canonical) {
		new_canonical = 0;

		for ( rr_iter = _getdns_rr_iter_init(&rr_iter_storage
							, req->response
							, req->response_len)
		    ; rr_iter && _getdns_rr_iter_section(rr_iter)
		              <= GLDNS_SECTION_ANSWER
		    ; rr_iter = _getdns_rr_iter_next(rr_iter)) {

			if (_getdns_rr_iter_section(rr_iter) !=
			    GLDNS_SECTION_ANSWER)
				continue;

			if (gldns_read_uint16(rr_iter->rr_type) !=
			    GETDNS_RRTYPE_CNAME)
				continue;

			owner_name = _getdns_owner_if_or_as_decompressed(
			    rr_iter, owner_name_space, &owner_name_len);
			if (!_getdns_dname_equal(canonical_name, owner_name))
				continue;

			if (!(rdf_iter = _getdns_rdf_iter_init(
			     &rdf_iter_storage, rr_iter)))
				continue;

			canonical_name = _getdns_rdf_if_or_as_decompressed(
			    rdf_iter,canonical_name_space,&canonical_name_len);
			new_canonical = 1;
		}
	}
	bindata.data = canonical_name;
	bindata.size = canonical_name_len;
	if (getdns_dict_set_bindata(result, "canonical_name", &bindata))
		goto error;

	goto success;
error:
	getdns_dict_destroy(result);
	result = NULL;
success:
	getdns_dict_destroy(header);
	getdns_dict_destroy(rr_dict);
	getdns_list_destroy(sections[GLDNS_SECTION_ADDITIONAL]);
	getdns_list_destroy(sections[GLDNS_SECTION_AUTHORITY]);
	getdns_list_destroy(sections[GLDNS_SECTION_ANSWER]);
	getdns_dict_destroy(question);
	return result;
}

getdns_dict *
_getdns_create_call_debugging_dict(
    getdns_context *context, getdns_network_req *netreq)
{
	getdns_bindata  qname;
	getdns_dict    *netreq_debug;
	getdns_dict    *address_debug = NULL;

	assert(netreq);

	/* It is the responsibility of the caller to free this */
	if (!(netreq_debug = getdns_dict_create_with_context(context)))
		return NULL;

	qname.data = netreq->owner->name;
	qname.size = netreq->owner->name_len;

	if (getdns_dict_set_bindata(netreq_debug, "query_name", &qname) ||
	    getdns_dict_set_int( netreq_debug, "query_type"
	                       , netreq->request_type ) ||

	    /* Safe, because uint32_t facilitates RRT's of almost 50 days*/
	    getdns_dict_set_int(netreq_debug, "run_time/ms",
		    (uint32_t)(( netreq->debug_end_time
	                       - netreq->debug_start_time)/1000))) {

		getdns_dict_destroy(netreq_debug);
		return NULL;

	} else if (!netreq->upstream)

		/* Nothing more for full recursion */
		return netreq_debug;


	/* Stub resolver debug data */
	_getdns_sockaddr_to_dict(
	    context, &netreq->upstream->addr, &address_debug);

	if (getdns_dict_set_dict(netreq_debug, "query_to", address_debug) ||
	    getdns_dict_set_int( netreq_debug, "transport"
	                       , netreq->upstream->transport)) {

		getdns_dict_destroy(address_debug);
		getdns_dict_destroy(netreq_debug);
		return NULL;
	}
	getdns_dict_destroy(address_debug);

	if (netreq->upstream->transport != GETDNS_TRANSPORT_TLS)
		return netreq_debug;
	
	/* Only include the auth status if TLS was used */
	if (getdns_dict_util_set_string(netreq_debug, "tls_auth_status",
	    netreq->debug_tls_auth_status == 0 ?
	    "OK: Hostname matched valid cert":"FAILED: Server not validated")){

		getdns_dict_destroy(netreq_debug);
		return NULL;
	}
	return netreq_debug;
}

getdns_dict *
_getdns_create_getdns_response(getdns_dns_req *completed_request)
{
	getdns_dict *result;
	getdns_list *just_addrs = NULL;
	getdns_list *replies_full;
	getdns_list *replies_tree;
	getdns_list *call_debugging = NULL;
	getdns_network_req *netreq, **netreq_p;
	int rrsigs_in_answer = 0;
	getdns_dict *reply;
	getdns_bindata *canonical_name = NULL;
	int nreplies = 0, nanswers = 0, nsecure = 0, ninsecure = 0, nbogus = 0;
    	getdns_bindata full_data;
	getdns_dict   *netreq_debug;

	/* info (bools) about dns_req */
	int dnssec_return_status;
	getdns_context *context;

	assert(completed_request);
	
	context = completed_request->context;
	if (!(result = getdns_dict_create_with_context(context)))
		return NULL;

	dnssec_return_status = completed_request->dnssec_return_status ||
	                       completed_request->dnssec_return_only_secure
#ifdef DNSSEC_ROADBLOCK_AVOIDANCE
	                    || completed_request->dnssec_roadblock_avoidance
#endif
	                       ;

	if (completed_request->netreqs[0]->request_type == GETDNS_RRTYPE_A ||
	    completed_request->netreqs[0]->request_type == GETDNS_RRTYPE_AAAA)
		just_addrs = getdns_list_create_with_context(
		    completed_request->context);

	if (getdns_dict_set_int(result, GETDNS_STR_KEY_ANSWER_TYPE,
	    GETDNS_NAMETYPE_DNS))
		goto error_free_result;
	
	if (!(replies_full = getdns_list_create_with_context(context)))
		goto error_free_result;

	if (!(replies_tree = getdns_list_create_with_context(context)))
		goto error_free_replies_full;

	if (completed_request->return_call_debugging &&
	    !(call_debugging = getdns_list_create_with_context(context)))
		goto error_free_replies_full;

	for ( netreq_p = completed_request->netreqs
	    ; (netreq = *netreq_p) ; netreq_p++) {

		if (! netreq->response_len)
			continue;

		nreplies++;
		if (netreq->dnssec_status == GETDNS_DNSSEC_SECURE)
			nsecure++;
		else if (netreq->dnssec_status != GETDNS_DNSSEC_BOGUS)
			ninsecure++;

		if (dnssec_return_status &&
		    netreq->dnssec_status == GETDNS_DNSSEC_BOGUS)
			nbogus++;


		if (! completed_request->dnssec_return_validation_chain) {
			if (dnssec_return_status &&
			    netreq->dnssec_status == GETDNS_DNSSEC_BOGUS)
				continue;
			else if (completed_request->dnssec_return_only_secure
			    && netreq->dnssec_status != GETDNS_DNSSEC_SECURE)
				continue;
		}
    		if (!(reply = _getdns_create_reply_dict(context,
		    netreq, just_addrs, &rrsigs_in_answer)))
			goto error;

		if (!canonical_name) {
			if (getdns_dict_get_bindata(
			    reply, "canonical_name", &canonical_name))
				goto error;
			if (getdns_dict_set_bindata(
			    result, "canonical_name", canonical_name))
				goto error;
		}
		/* TODO: Check instead if canonical_name for request_type
		 *       is in the answer section.
		 */
		if (GLDNS_RCODE_NOERROR ==
		    GLDNS_RCODE_WIRE(netreq->response))
			nanswers++;

		if (dnssec_return_status ||
		    completed_request->dnssec_return_validation_chain) {

			if (getdns_dict_set_int(reply, "dnssec_status",
			    netreq->dnssec_status))
				goto error;
		}

    		if (_getdns_list_append_dict(replies_tree, reply)) {
    			getdns_dict_destroy(reply);
			goto error;
		}
		
		if (call_debugging) {
			if (!(netreq_debug =
			   _getdns_create_call_debugging_dict(context,netreq)))
				goto error;

			if (_getdns_list_append_dict(
			    call_debugging, netreq_debug)) {

				getdns_dict_destroy(netreq_debug);
				goto error;
			}
			getdns_dict_destroy(netreq_debug);
		}

    		getdns_dict_destroy(reply);

    		/* buffer */
		full_data.data = netreq->response;
		full_data.size = netreq->response_len;
		if (_getdns_list_append_bindata(replies_full, &full_data))
			goto error;
    	}
    	if (getdns_dict_set_list(result, "replies_tree", replies_tree))
		goto error;
	getdns_list_destroy(replies_tree);

	if (call_debugging &&
	    getdns_dict_set_list(result, "call_debugging", call_debugging))
	    goto error_free_call_debugging;

	if (getdns_dict_set_list(result, "replies_full", replies_full))
		goto error_free_replies_full;
	getdns_list_destroy(replies_full);

	if (just_addrs && getdns_dict_set_list(
	    result, GETDNS_STR_KEY_JUST_ADDRS, just_addrs))
		goto error_free_result;
	getdns_list_destroy(just_addrs);

	if (getdns_dict_set_int(result, GETDNS_STR_KEY_STATUS,
	    nreplies == 0   ? GETDNS_RESPSTATUS_ALL_TIMEOUT :
	    completed_request->dnssec_return_only_secure && nsecure == 0 && ninsecure > 0
	                    ? GETDNS_RESPSTATUS_NO_SECURE_ANSWERS :
	    completed_request->dnssec_return_only_secure && nsecure == 0 && nbogus > 0
	                    ? GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS :
	    nanswers == 0   ? GETDNS_RESPSTATUS_NO_NAME
	                    : GETDNS_RESPSTATUS_GOOD))
		goto error_free_result;

	return result;
error:
	/* cleanup */
	getdns_list_destroy(replies_tree);
error_free_call_debugging:
	getdns_list_destroy(call_debugging);
error_free_replies_full:
	getdns_list_destroy(replies_full);
error_free_result:
	getdns_list_destroy(just_addrs);
	getdns_dict_destroy(result);
	return NULL;
}

static int
extformatcmp(const void *a, const void *b)
{
	return strcmp(((getdns_extension_format *) a)->extstring,
	    ((getdns_extension_format *) b)->extstring);
}

/*---------------------------------------- validate_extensions */
getdns_return_t
_getdns_validate_extensions(struct getdns_dict * extensions)
{
	struct getdns_dict_item *item;
	getdns_extension_format *extformat;

	if (extensions)
		RBTREE_FOR(item, struct getdns_dict_item *,
		    &(extensions->root)) {

			getdns_extension_format key;
			key.extstring = (char *) item->node.key;
			extformat = bsearch(&key, extformats,
			    sizeof(extformats) /
			    sizeof(getdns_extension_format),
			    sizeof(getdns_extension_format), extformatcmp);
			if (!extformat)
				return GETDNS_RETURN_NO_SUCH_EXTENSION;

			if (item->i.dtype != extformat->exttype)
				return GETDNS_RETURN_EXTENSION_MISFORMAT;
		}
	return GETDNS_RETURN_GOOD;
}				/* _getdns_validate_extensions */

#ifdef HAVE_LIBUNBOUND
getdns_return_t
getdns_apply_network_result(getdns_network_req* netreq,
    struct ub_result* ub_res)
{
	if (ub_res->bogus)
		netreq->dnssec_status = GETDNS_DNSSEC_BOGUS;
	else if (ub_res->secure)
		netreq->dnssec_status = GETDNS_DNSSEC_SECURE;
	else if (netreq->owner->context->trust_anchors)
		netreq->dnssec_status = GETDNS_DNSSEC_INSECURE;

	if (ub_res == NULL) /* Timeout */
		return GETDNS_RETURN_GOOD;

	if (ub_res->answer_packet) {
		if (netreq->max_udp_payload_size < ub_res->answer_len)
			netreq->response = GETDNS_XMALLOC(
			    netreq->owner->context->mf,
			    uint8_t, ub_res->answer_len
			);
		(void) memcpy(netreq->response, ub_res->answer_packet,
		    (netreq->response_len = ub_res->answer_len));
		return GETDNS_RETURN_GOOD;
	}

    	if (ub_res->rcode == GETDNS_RCODE_SERVFAIL) {
		/* Likely to be caused by timeout from a synchronous
		 * lookup.  Don't forge a packet.
		 */
		return GETDNS_RETURN_GOOD;
	}
	/* Likely to be because libunbound refused the request
	 * so ub_res->answer_packet=NULL, ub_res->answer_len=0
	 * So we need to create an answer packet.
	 */
	gldns_write_uint16(netreq->response    , 0); /* query_id */
	gldns_write_uint16(netreq->response + 2, 0); /* reset all flags */
	gldns_write_uint16(netreq->response + GLDNS_QDCOUNT_OFF, 1);
	gldns_write_uint16(netreq->response + GLDNS_ANCOUNT_OFF, 0);
	gldns_write_uint16(netreq->response + GLDNS_NSCOUNT_OFF, 0);
	gldns_write_uint16(netreq->response + GLDNS_ARCOUNT_OFF, 0);

	GLDNS_OPCODE_SET(netreq->response, 3);
	GLDNS_QR_SET(netreq->response);
	GLDNS_RD_SET(netreq->response);
	GLDNS_RA_SET(netreq->response);
	GLDNS_RCODE_SET(netreq->response, ub_res->rcode);

	(void) memcpy( netreq->response + GLDNS_HEADER_SIZE
	             , netreq->owner->name, netreq->owner->name_len);

	gldns_write_uint16( netreq->response + GLDNS_HEADER_SIZE
	                                     + netreq->owner->name_len
	                  , netreq->request_type);
	gldns_write_uint16( netreq->response + GLDNS_HEADER_SIZE
	                                     + netreq->owner->name_len + 2
	                  , netreq->request_class);

	netreq->response_len = GLDNS_HEADER_SIZE + netreq->owner->name_len + 4;

	return GETDNS_RETURN_GOOD;
}
#endif


getdns_return_t
_getdns_validate_dname(const char* dname) {
    int len;
    int label_len;
    const char* s;
    if (dname == NULL) {
        return GETDNS_RETURN_INVALID_PARAMETER;
    }
    len = strlen(dname);
    if (len > GETDNS_MAX_DNAME_LEN * 4 || len == 0) {
        return GETDNS_RETURN_BAD_DOMAIN_NAME;
    }
    if (len == 1 && dname[0] == '.') {
        /* root is ok */
        return GETDNS_RETURN_GOOD;
    }
	/* By specification [RFC1035] the total length of a DNS label is
	 * restricted to 63 octets and must be larger than 0 (except for the
	 * final root-label).  The total length of a domain name (i.e., label
	 * octets and label length octets) is restricted to 255 octets or less.
	 * With a fully qualified domain name this includes the last label
	 * length octet for the root label.  In a normalized representation the
	 * number of labels (including the root) plus the number of octets in
	 * each label may not be larger than 255.
	 */
    len = 0;
    label_len = 0;
    for (s = dname; *s; ++s) {
        switch (*s) {
            case '.':
                if (label_len > GETDNS_MAX_LABEL_LEN ||
                    label_len == 0) {
                    return GETDNS_RETURN_BAD_DOMAIN_NAME;
                }
                label_len = 0;
		len += 1;
                break;
	    case '\\':
		s += 1;
		if (isdigit(s[0])) {
			/* octet value */
			if (! isdigit(s[1]) && ! isdigit(s[2]))
				return GETDNS_RETURN_BAD_DOMAIN_NAME;

			if ((s[0] - '0') * 100 +
			    (s[1] - '0') * 10 + (s[2] - '0') > 255)
				return GETDNS_RETURN_BAD_DOMAIN_NAME;

			s += 2;
		}
		/* else literal char (1 octet) */
		label_len++;
		len += 1;
		break;
            default:
                label_len++;
		len += 1;
                break;
        }
    }
    if (len > GETDNS_MAX_DNAME_LEN || label_len > GETDNS_MAX_LABEL_LEN) {
        return GETDNS_RETURN_BAD_DOMAIN_NAME;
    }
    return GETDNS_RETURN_GOOD;
} /* _getdns_validate_dname */


static void _getdns_reply2wire_buf(gldns_buffer *buf, getdns_dict *reply)
{
	getdns_dict *rr_dict, *q_dict, *h_dict;
	getdns_list *section;
	size_t i, pkt_start, ancount, nscount;
	uint32_t qtype, qclass = GETDNS_RRCLASS_IN, rcode = GETDNS_RCODE_NOERROR;
	getdns_bindata *qname;


	pkt_start = gldns_buffer_position(buf);
	/* Empty header */
	gldns_buffer_write_u32(buf, 0);
	gldns_buffer_write_u32(buf, 0);
	gldns_buffer_write_u32(buf, 0);

	if (   !getdns_dict_get_dict(reply, "question", &q_dict)
	    && !getdns_dict_get_int(q_dict, "qtype", &qtype)
	    && !getdns_dict_get_bindata(q_dict, "qname", &qname)) {

		gldns_buffer_write(buf, qname->data, qname->size);
		gldns_buffer_write_u16(buf, (uint16_t)qtype);
		gldns_buffer_write_u16(buf, (uint16_t)qclass);
		gldns_buffer_write_u16_at(
		    buf, pkt_start + GLDNS_QDCOUNT_OFF, 1);
	}

	if (   !getdns_dict_get_dict(reply, "header", &h_dict)
	    && !getdns_dict_get_int(h_dict, "rcode", &rcode)) {

		GLDNS_RCODE_SET(gldns_buffer_at(buf, pkt_start), rcode);
	}
	if (!getdns_dict_get_list(reply, "answer", &section)) {
		for ( i = 0, ancount = 0
		    ; !getdns_list_get_dict(section, i, &rr_dict)
		    ; i++ ) {

			if (!_getdns_rr_dict2wire(rr_dict, buf))
				ancount++;
		}
		gldns_buffer_write_u16_at(
		    buf, pkt_start + GLDNS_ANCOUNT_OFF, ancount);
	}
	if (!getdns_dict_get_list(reply, "authority", &section)) {
		for ( i = 0, nscount = 0
		    ; !getdns_list_get_dict(section, i, &rr_dict)
		    ; i++ ) {

			if (!_getdns_rr_dict2wire(rr_dict, buf))
				nscount++;
		}
		gldns_buffer_write_u16_at(
		    buf, pkt_start + GLDNS_NSCOUNT_OFF, nscount);
	}
}

static void _getdns_list2wire_buf(gldns_buffer *buf, getdns_list *l)
{
	getdns_dict *rr_dict;
	size_t i, pkt_start, ancount;
	uint32_t qtype, qclass = GETDNS_RRCLASS_IN;
	getdns_bindata *qname;

	pkt_start = gldns_buffer_position(buf);
	/* Empty header */
	gldns_buffer_write_u32(buf, 0);
	gldns_buffer_write_u32(buf, 0);
	gldns_buffer_write_u32(buf, 0);

	for ( i = 0
	    ; !getdns_list_get_dict(l, i, &rr_dict)
	    ; i++ ) {

		if (getdns_dict_get_int(rr_dict, "qtype", &qtype) ||
		    getdns_dict_get_bindata(rr_dict, "qname", &qname))
			continue;
		(void) getdns_dict_get_int(rr_dict, "qclass", &qclass);
		gldns_buffer_write(buf, qname->data, qname->size);
		gldns_buffer_write_u16(buf, (uint16_t)qtype);
		gldns_buffer_write_u16(buf, (uint16_t)qclass);
		gldns_buffer_write_u16_at(buf, pkt_start+GLDNS_QDCOUNT_OFF, 1);
		break;
	}
	for ( i = 0, ancount = 0
	    ; !getdns_list_get_dict(l, i, &rr_dict)
	    ; i++ ) {

		if (!_getdns_rr_dict2wire(rr_dict, buf))
			ancount++;
	}
	gldns_buffer_write_u16_at(buf, pkt_start+GLDNS_ANCOUNT_OFF, ancount);
}

uint8_t *_getdns_list2wire(
    getdns_list *l, uint8_t *buf, size_t *buf_len, struct mem_funcs *mf)
{
	gldns_buffer gbuf;
	size_t sz;

	gldns_buffer_init_frm_data(&gbuf, buf, *buf_len);
	_getdns_list2wire_buf(&gbuf, l);

	if ((sz = gldns_buffer_position(&gbuf)) <= *buf_len) {
		*buf_len = sz;
		return buf;
	}
	if (!(buf = GETDNS_XMALLOC(*mf, uint8_t, (*buf_len = sz))))
		return NULL;

	gldns_buffer_init_frm_data(&gbuf, buf, sz);
	_getdns_list2wire_buf(&gbuf, l);
	return buf;
}

uint8_t *_getdns_reply2wire(
    getdns_dict *r, uint8_t *buf, size_t *buf_len, struct mem_funcs *mf)
{
	gldns_buffer gbuf;
	size_t sz;

	gldns_buffer_init_frm_data(&gbuf, buf, *buf_len);
	_getdns_reply2wire_buf(&gbuf, r);

	if ((sz = gldns_buffer_position(&gbuf)) <= *buf_len) {
		*buf_len = sz;
		return buf;
	}
	if (!(buf = GETDNS_XMALLOC(*mf, uint8_t, (*buf_len = sz))))
		return NULL;

	gldns_buffer_init_frm_data(&gbuf, buf, sz);
	_getdns_reply2wire_buf(&gbuf, r);
	return buf;
}

void _getdns_wire2list(uint8_t *pkt, size_t pkt_len, getdns_list *l)
{
	_getdns_rr_iter rr_spc, *rr;
	getdns_dict *rr_dict;

	for ( rr = _getdns_rr_iter_init(&rr_spc, pkt, pkt_len)
	    ; rr ; rr = _getdns_rr_iter_next(rr)) {

		if (!(rr_dict = _getdns_rr_iter2rr_dict(&l->mf, rr)))
			continue;

		(void)_getdns_list_append_dict(l, rr_dict);
		getdns_dict_destroy(rr_dict);
	}
}

/* util-internal.c */
