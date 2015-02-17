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
#include <ldns/rbtree.h>
#include <unbound.h>
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
#include "rr-iter.h"

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
	{"return_api_information", t_int},
	{"return_both_v4_and_v6", t_int},
	{"return_call_debugging", t_int},
	{"specify_class", t_int},
};

static struct getdns_bindata IPv4_str_bindata = { 5, (void *)"IPv4" };
static struct getdns_bindata IPv6_str_bindata = { 5, (void *)"IPv6" };

getdns_return_t
getdns_dict_util_set_string(struct getdns_dict * dict, char *name, const char *value)
{
	/* account for the null term */
	if (value == NULL) {
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
	}
	struct getdns_bindata type_bin = { strlen(value) + 1, (uint8_t *) value };
	return getdns_dict_set_bindata(dict, name, &type_bin);
}

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
dict_to_sockaddr(struct getdns_dict * ns, struct sockaddr_storage * output)
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
sockaddr_to_dict(struct getdns_context *context, struct sockaddr_storage *address,
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

/* result must be freed */
static char *
convert_rdf_to_str(ldns_rdf * rdf)
{
	if (ldns_rdf_get_type(rdf) == LDNS_RDF_TYPE_DNAME) {
		ldns_dname2canonical(rdf);
	}
	return ldns_rdf2str(rdf);
}

#define SET_WIRE_INT(X,Y) if (getdns_dict_set_int(result, #X , (int) \
                              GLDNS_ ## Y ## _WIRE(netreq->response))) break
#define SET_WIRE_CNT(X,Y) if (getdns_dict_set_int(result, #X , (int) \
                              GLDNS_ ## Y (netreq->response))) break

/* create the header dict */
static struct getdns_dict *
create_reply_header_dict(getdns_context *context, getdns_network_req *netreq)
{
	/* { "id": 23456, "qr": 1, "opcode": 0, ... }, */
	struct getdns_dict *result = getdns_dict_create_with_context(context);

	if (!result)
		return NULL;
    	do {
		SET_WIRE_INT(id, ID);
		SET_WIRE_INT(qr, QR);
		SET_WIRE_INT(aa, AA);
		SET_WIRE_INT(tc, TC);
		SET_WIRE_INT(rd, RD);
		SET_WIRE_INT(cd, CD);
		SET_WIRE_INT(ra, RA);
		SET_WIRE_INT(ad, AD);
		SET_WIRE_INT(opcode, OPCODE);
		SET_WIRE_INT(rcode, RCODE);
		SET_WIRE_INT(z, Z);

		SET_WIRE_CNT(qdcount, QDCOUNT);
		SET_WIRE_CNT(ancount, ANCOUNT);
		SET_WIRE_CNT(nscount, NSCOUNT);
		SET_WIRE_CNT(arcount, ARCOUNT);

		return result;

	} while (0);

	getdns_dict_destroy(result);
	return NULL;
}

/* helper to convert an rr_list to getdns_list.
   returns a list of objects where each object
   is a result from create_dict_from_rr */
struct getdns_list *
create_list_from_rr_list(struct getdns_context *context, ldns_rr_list * rr_list)
{
	size_t i = 0;
	size_t idx = 0;
	int r = GETDNS_RETURN_GOOD;
	struct getdns_list *result = getdns_list_create_with_context(context);
	struct getdns_dict *rrdict;
	for (i = 0; i < ldns_rr_list_rr_count(rr_list) && r == GETDNS_RETURN_GOOD;
	    ++i) {
		ldns_rr *rr = ldns_rr_list_rr(rr_list, i);
		r = priv_getdns_create_dict_from_rr(context, rr, &rrdict);
		if (r != GETDNS_RETURN_GOOD)
			break; /* Could not create, do not destroy */
		r = getdns_list_add_item(result, &idx);
		if (r == GETDNS_RETURN_GOOD)
			r = getdns_list_set_dict(result, idx, rrdict);
		getdns_dict_destroy(rrdict);
	}
	if (r != GETDNS_RETURN_GOOD) {
		getdns_list_destroy(result);
		result = NULL;
	}
	return result;
}

/* helper to add the ipv4 or ipv6 bin data to the list of addrs */
static getdns_return_t
add_only_addresses(struct getdns_list * addrs, ldns_rr_list * rr_list)
{
	int r = GETDNS_RETURN_GOOD;
	size_t i = 0;
	size_t item_idx = 0;

	r = getdns_list_get_length(addrs, &item_idx);
	for (i = 0; r == GETDNS_RETURN_GOOD &&
	            i < ldns_rr_list_rr_count(rr_list); ++i) {
		ldns_rr *rr = ldns_rr_list_rr(rr_list, i);
		size_t j = 0;
		size_t rd_count = ldns_rr_rd_count(rr);
		for (j = 0; r == GETDNS_RETURN_GOOD && j < rd_count; ++j) {
			ldns_rdf *rdf = ldns_rr_rdf(rr, j);
			if (ldns_rdf_get_type(rdf) != LDNS_RDF_TYPE_A &&
			    ldns_rdf_get_type(rdf) != LDNS_RDF_TYPE_AAAA) {
				continue;
			}
			struct getdns_dict *this_address =
			    getdns_dict_create_with_extended_memory_functions(
				addrs->mf.mf_arg,
				addrs->mf.mf.ext.malloc,
				addrs->mf.mf.ext.realloc,
				addrs->mf.mf.ext.free);
			if (this_address == NULL) {
				r = GETDNS_RETURN_MEMORY_ERROR;
				break;
			}
			struct getdns_bindata rbin =
				{ ldns_rdf_size(rdf), ldns_rdf_data(rdf) };
			r = getdns_dict_set_bindata(this_address,
			    GETDNS_STR_ADDRESS_TYPE,
			    ( ldns_rdf_get_type(rdf) == LDNS_RDF_TYPE_A
			    ?  &IPv4_str_bindata : &IPv6_str_bindata));
            if (r != GETDNS_RETURN_GOOD) {
                getdns_dict_destroy(this_address);
                break;
            }

			r = getdns_dict_set_bindata(this_address,
			    GETDNS_STR_ADDRESS_DATA, &rbin);
            if (r != GETDNS_RETURN_GOOD) {
                getdns_dict_destroy(this_address);
                break;
            }

			r = getdns_list_set_dict(addrs, item_idx++,
			    this_address);
			getdns_dict_destroy(this_address);
		}
	}
	return r;
}

getdns_dict *
priv_getdns_rr_iter2rr_dict(getdns_context *context, priv_getdns_rr_iter *i)
{
	getdns_dict *rr_dict, *rdata_dict;
	getdns_bindata bindata;
	uint32_t int_val = 0;
	getdns_data_type val_type;
	priv_getdns_rdf_iter rdf_storage, *rdf;
	getdns_list *repeat_list = NULL;
	getdns_dict *repeat_dict = NULL;
	uint8_t ff_bytes[256];
	uint16_t rr_type;

	assert(context);
	assert(i);
	if (!(rr_dict = getdns_dict_create_with_context(context)))
		return NULL;

	bindata.data = priv_getdns_owner_if_or_as_decompressed(
	    i, ff_bytes, &bindata.size);

	/* question */
	if (priv_getdns_rr_iter_section(i) == GLDNS_SECTION_QUESTION) {

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
	if (!(rdata_dict = getdns_dict_create_with_context(context)))
		goto error;

	if ((rdf = priv_getdns_rdf_iter_init(&rdf_storage, i))) {
		bindata.size = rdf->end - rdf->pos;
		bindata.data = rdf->pos;
		if (getdns_dict_set_bindata(rdata_dict, "rdata_raw", &bindata))
			goto rdata_error;
	}
	for (; rdf; rdf = priv_getdns_rdf_iter_next(rdf)) {
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
		} else if ((rdf->rdd_pos->type & GETDNS_RDF_DNAME) ==
		    GETDNS_RDF_DNAME) {
			val_type = t_bindata;

			bindata.data = priv_getdns_rdf_if_or_as_decompressed(
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
		} else
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
			default:
				break;
			}
			continue;

		} else if (rdf->rdd_pos == rdf->rdd_repeat) {
			/* list with rdf values */

			if (! repeat_list && !(repeat_list =
			    getdns_list_create_with_context(context)))
				goto rdata_error;
			
			switch (val_type) {
			case t_int:
				if (getdns_list_append_int(repeat_list,
				    int_val))
					goto rdata_error;
				break;
			case t_bindata:
				if (getdns_list_append_bindata(repeat_list,
				    &bindata))
					goto rdata_error;
				break;
			default:
				break;
			}
			continue;

		}
		/* list with dicts with rdf values */
		if (rdf->rdd_pos == rdf->rdd_repeat + 1) {

			if (repeat_dict) {
				if (getdns_list_append_dict(
				    repeat_list, repeat_dict))
					goto rdata_error;

				getdns_dict_destroy(repeat_dict);
				repeat_dict = NULL;
			}
			if (!(repeat_dict =
			    getdns_dict_create_with_context(context)))
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
		default:
			break;
		}
	}
	if (repeat_dict) {
		if (getdns_list_append_dict(repeat_list, repeat_dict))
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

	return rr_dict;

rdata_error:
	getdns_list_destroy(repeat_list);
	getdns_dict_destroy(repeat_dict);
	getdns_dict_destroy(rdata_dict);
error:
	getdns_dict_destroy(rr_dict);
	return NULL;
}

static int
dname_equal(uint8_t *s1, uint8_t *s2)
{
	uint8_t i;
	for (;;) {
		if (*s1 != *s2)
			return 0;
		else if (!*s1)
			return 1;
		for (i = *s1++, s2++; i > 0; i--, s1++, s2++)
			if ((*s1 & 0xDF) != (*s2 & 0xDF))
				return 0;
	}
}

static getdns_dict *
create_reply_dict(getdns_context *context, getdns_network_req *req,
    getdns_list *just_addrs)
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
	priv_getdns_rr_iter rr_iter_storage, *rr_iter;
	priv_getdns_rdf_iter rdf_iter_storage, *rdf_iter;
	getdns_bindata bindata;
	gldns_pkt_section section;
	uint8_t canonical_name_space[256],
	       *canonical_name = canonical_name_space;
	uint8_t owner_name_space[256], *owner_name;
	size_t canonical_name_len = 256, owner_name_len;
	int new_canonical = 0;

	if (!result)
		goto error;


	/* header */
    	if ((r = getdns_dict_set_dict(result, GETDNS_STR_KEY_HEADER,
	    create_reply_header_dict(context, req))))
		goto error;

	(void) gldns_str2wire_dname_buf(
	    req->owner->name, canonical_name_space, &canonical_name_len);

	for ( rr_iter = priv_getdns_rr_iter_init(&rr_iter_storage
	                                        , req->response
	                                        , req->response_len)
	    ; rr_iter
	    ; rr_iter = priv_getdns_rr_iter_next(rr_iter)) {

		if (!(rr_dict = priv_getdns_rr_iter2rr_dict(context, rr_iter)))
			continue;

		section = priv_getdns_rr_iter_section(rr_iter);
		if (section == GLDNS_SECTION_QUESTION) {

			if (getdns_dict_set_dict(result, "question", rr_dict))
				goto error;
			continue;
		}
		if (getdns_list_append_dict(sections[section], rr_dict))
			goto error;

		rr_dict = NULL;

		if (section != GLDNS_SECTION_ANSWER)
			continue;

		if (gldns_read_uint16(rr_iter->rr_type)==GETDNS_RRTYPE_CNAME) {

			owner_name = priv_getdns_owner_if_or_as_decompressed(
			    rr_iter, owner_name_space, &owner_name_len);
			if (!dname_equal(canonical_name, owner_name))
				continue;

			if (!(rdf_iter = priv_getdns_rdf_iter_init(
			     &rdf_iter_storage, rr_iter)))
				continue;

			new_canonical = 1;
			canonical_name = priv_getdns_rdf_if_or_as_decompressed(
			    rdf_iter,canonical_name_space,&canonical_name_len);
			continue;
		}

		/* TODO: Get canonical name_from ANSWER RR's */
		if (gldns_read_uint16(rr_iter->rr_type) != GETDNS_RRTYPE_A &&
		    gldns_read_uint16(rr_iter->rr_type) != GETDNS_RRTYPE_AAAA)
			continue;

		if (!(rdf_iter = priv_getdns_rdf_iter_init(
		     &rdf_iter_storage, rr_iter)))
			continue;

		bindata.size = rdf_iter->nxt - rdf_iter->pos;
		bindata.data = rdf_iter->pos;
		if (!(rr_dict = getdns_dict_create_with_context(context)) ||

		    getdns_dict_set_bindata(rr_dict, "address_type",
		    gldns_read_uint16(rr_iter->rr_type) == GETDNS_RRTYPE_A ?
		    &IPv4_str_bindata : &IPv6_str_bindata) ||

		    getdns_dict_set_bindata(rr_dict, "address_data",&bindata)||

		    getdns_list_append_dict(just_addrs, rr_dict)) {

			goto error;
		}
		getdns_dict_destroy(rr_dict);
		rr_dict = NULL;

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

		for ( rr_iter = priv_getdns_rr_iter_init(&rr_iter_storage
							, req->response
							, req->response_len)
		    ; rr_iter && priv_getdns_rr_iter_section(rr_iter)
		              <= GLDNS_SECTION_ANSWER
		    ; rr_iter = priv_getdns_rr_iter_next(rr_iter)) {

			if (priv_getdns_rr_iter_section(rr_iter) !=
			    GLDNS_SECTION_ANSWER)
				continue;

			if (gldns_read_uint16(rr_iter->rr_type) !=
			    GETDNS_RRTYPE_CNAME)
				continue;

			owner_name = priv_getdns_owner_if_or_as_decompressed(
			    rr_iter, owner_name_space, &owner_name_len);
			if (!dname_equal(canonical_name, owner_name))
				continue;

			if (!(rdf_iter = priv_getdns_rdf_iter_init(
			     &rdf_iter_storage, rr_iter)))
				continue;

			canonical_name = priv_getdns_rdf_if_or_as_decompressed(
			    rdf_iter,canonical_name_space,&canonical_name_len);
			new_canonical = 1;
		}
	}
	bindata.data = canonical_name;
	bindata.size = canonical_name_len;
	if (getdns_dict_set_bindata(result, "canonical_name", &bindata))
		goto error;

	return result;
error:
	getdns_dict_destroy(rr_dict);
	getdns_list_destroy(sections[3]);
	getdns_list_destroy(sections[2]);
	getdns_list_destroy(sections[1]);
	getdns_dict_destroy(question);
	getdns_dict_destroy(result);
	return NULL;
}

static char *
get_canonical_name(const char *name)
{
	ldns_rdf *rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, name);
	if (!rdf) {
		return NULL;
	}
	char *result = convert_rdf_to_str(rdf);
	ldns_rdf_deep_free(rdf);
	return result;
}

static int
rrsigs_in_answer(ldns_pkt *pkt)
{
	ldns_rr_list *rr_list = ldns_pkt_answer(pkt);
	size_t i;

	if (! rr_list)
		return 0;

	for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++)
		if (LDNS_RR_TYPE_RRSIG ==
		    ldns_rr_get_type(ldns_rr_list_rr(rr_list, i)))
			return 1;
	return 0;
}

struct getdns_dict *
create_getdns_response(getdns_dns_req *completed_request)
{
	getdns_dict *result = getdns_dict_create_with_context(
	    completed_request->context);
	getdns_list *replies_full = getdns_list_create_with_context(
	    completed_request->context);
	getdns_list *just_addrs = NULL;
	getdns_list *replies_tree = getdns_list_create_with_context(
	    completed_request->context);
	getdns_network_req *netreq, **netreq_p;
	char *canonical_name = NULL;
	getdns_return_t r = 0;
	int nreplies = 0, nanswers = 0, nsecure = 0, ninsecure = 0, nbogus = 0;
    	struct getdns_bindata full_data;

	/* info (bools) about dns_req */
	int dnssec_return_status;

    	for ( netreq_p = completed_request->netreqs
	    ; ! r && (netreq = *netreq_p)
	    ; netreq_p++) {

		if (! netreq->response_len)
			continue;

		if (ldns_wire2pkt(&(netreq->result), netreq->response,
		    netreq->response_len)) {

			netreq->response_len = 0;
			continue;
		}
	}

	dnssec_return_status = completed_request->dnssec_return_status ||
	                       completed_request->dnssec_return_only_secure;

	if (completed_request->netreqs[0]->request_type == GETDNS_RRTYPE_A ||
	    completed_request->netreqs[0]->request_type == GETDNS_RRTYPE_AAAA)
		just_addrs = getdns_list_create_with_context(
		    completed_request->context);

    do {
    	canonical_name = get_canonical_name(completed_request->name);
    	r = getdns_dict_util_set_string(result, GETDNS_STR_KEY_CANONICAL_NM,
    	    canonical_name);
    	free(canonical_name);
        if (r != GETDNS_RETURN_GOOD) {
            break;
        }

    	r = getdns_dict_set_int(result, GETDNS_STR_KEY_ANSWER_TYPE,
    	    GETDNS_NAMETYPE_DNS);
        if (r != GETDNS_RETURN_GOOD) {
            break;
        }

    	for ( netreq_p = completed_request->netreqs
	    ; ! r && (netreq = *netreq_p)
	    ; netreq_p++) {

		if (! netreq->response_len)
			continue;

		nreplies++;
		if (netreq->secure)
			nsecure++;
		else if (! netreq->bogus)
			ninsecure++;
		if (dnssec_return_status && netreq->bogus)
			nbogus++;
		else if (LDNS_RCODE_NOERROR ==
		    GLDNS_RCODE_WIRE(netreq->response))
			nanswers++;

		if (! completed_request->dnssec_return_validation_chain) {
			if (dnssec_return_status && netreq->bogus)
				continue;
			else if (completed_request->dnssec_return_only_secure && ! netreq->secure)
				continue;
		}
    		size_t idx = 0;
    		/* reply tree */
    		struct getdns_dict *reply = create_reply_dict(
    		    completed_request->context, netreq, just_addrs);

		if (! reply) {
			r = GETDNS_RETURN_MEMORY_ERROR;
			break;
		}
		if (dnssec_return_status || completed_request->dnssec_return_validation_chain) {
			r = getdns_dict_set_int(reply, "dnssec_status",
			    ( netreq->secure   ? GETDNS_DNSSEC_SECURE
			    : netreq->bogus    ? GETDNS_DNSSEC_BOGUS
			    : rrsigs_in_answer(netreq->result) &&
			      completed_request->context->has_ta
			                       ? GETDNS_DNSSEC_INDETERMINATE
					       : GETDNS_DNSSEC_INSECURE ));

			if (r != GETDNS_RETURN_GOOD) {
                		getdns_dict_destroy(reply);
				break;
			}
		}
    		r = getdns_list_add_item(replies_tree, &idx);
            if (r != GETDNS_RETURN_GOOD) {
                getdns_dict_destroy(reply);
                // break inner while
                break;
            }

    		r = getdns_list_set_dict(replies_tree, idx, reply);
    		getdns_dict_destroy(reply);
            if (r != GETDNS_RETURN_GOOD) {
                // break inner while
                break;
            }
    		/* buffer */
			r = getdns_list_add_item(replies_full, &idx);
            if (r != GETDNS_RETURN_GOOD) {
                // break inner while
                break;
            }
			full_data.data = netreq->response;
			full_data.size = netreq->response_len;
			r = getdns_list_set_bindata(replies_full, idx,
			    &full_data);
            if (r != GETDNS_RETURN_GOOD) {
                free(full_data.data);
                // break inner while
                break;
            }
    	}

        if (r != GETDNS_RETURN_GOOD)
            break;

    	r = getdns_dict_set_list(result, GETDNS_STR_KEY_REPLIES_TREE,
    	    replies_tree);
        if (r != GETDNS_RETURN_GOOD)
            break;

    	r = getdns_dict_set_list(result, GETDNS_STR_KEY_REPLIES_FULL,
    	    replies_full);
        if (r != GETDNS_RETURN_GOOD)
            break;

    	if (just_addrs) {
    		r = getdns_dict_set_list(result, GETDNS_STR_KEY_JUST_ADDRS,
    		    just_addrs);
		if (r != GETDNS_RETURN_GOOD) {
		    break;
		}
    	}
    	r = getdns_dict_set_int(result, GETDNS_STR_KEY_STATUS,
	    nreplies == 0   ? GETDNS_RESPSTATUS_ALL_TIMEOUT :
	    completed_request->dnssec_return_only_secure && nsecure == 0 && ninsecure > 0
	                    ? GETDNS_RESPSTATUS_NO_SECURE_ANSWERS :
	    completed_request->dnssec_return_only_secure && nsecure == 0 && nbogus > 0
	                    ? GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS :
	    nanswers == 0   ? GETDNS_RESPSTATUS_NO_NAME
	                    : GETDNS_RESPSTATUS_GOOD);
    } while (0);

	/* cleanup */
	getdns_list_destroy(replies_tree);
	getdns_list_destroy(replies_full);
	getdns_list_destroy(just_addrs);

	if (r != 0) {
		getdns_dict_destroy(result);
		result = NULL;
	}

	return result;
}

/*This method can be used when e.g. a local lookup has been performed and the 
   result is simply a list of addresses (not a DNS packet)*/
struct getdns_dict *
create_getdns_response_from_rr_list(struct getdns_dns_req * completed_request,
                                    ldns_rr_list * response_list)
{
	struct getdns_dict *result = getdns_dict_create_with_context(completed_request->context);
	struct getdns_list *replies_full = getdns_list_create_with_context(
	    completed_request->context);
	struct getdns_list *replies_tree = getdns_list_create_with_context(
	    completed_request->context);
	struct getdns_list *just_addrs = NULL;
	char *canonical_name = NULL;
	getdns_return_t r = 0;

	/* NOTE: With DNS packet, we ignore any DNSSEC related extensions since we 
	   don't populate the replies full or tree at all*/

	just_addrs = getdns_list_create_with_context(completed_request->context);

	do {
		canonical_name = get_canonical_name(completed_request->name);
		r = getdns_dict_util_set_string(result, GETDNS_STR_KEY_CANONICAL_NM,
			canonical_name);
		free(canonical_name);
		if (r != GETDNS_RETURN_GOOD) {
			break;
		}

		/* For local lookups we don't set an answer_type as there isn't a
		suitable one*/

		r = add_only_addresses(just_addrs, response_list);
		if (r != GETDNS_RETURN_GOOD) {
			break;
		}
           
		if (r != GETDNS_RETURN_GOOD)
			break;

		r = getdns_dict_set_list(result, GETDNS_STR_KEY_REPLIES_TREE,
			replies_tree);
		if (r != GETDNS_RETURN_GOOD)
            break;

		r = getdns_dict_set_list(result, GETDNS_STR_KEY_REPLIES_FULL,
			replies_full);
		if (r != GETDNS_RETURN_GOOD)
			break;

		r = getdns_dict_set_list(result, GETDNS_STR_KEY_JUST_ADDRS,
			just_addrs);
		if (r != GETDNS_RETURN_GOOD) {
            break;
		}

		r = getdns_dict_set_int(result, GETDNS_STR_KEY_STATUS,
				GETDNS_RESPSTATUS_GOOD);
	} while (0);

	/* cleanup */
	getdns_list_destroy(replies_tree);
	getdns_list_destroy(replies_full);
	getdns_list_destroy(just_addrs);

	if (r != 0) {
		getdns_dict_destroy(result);
		result = NULL;
	}

	return result;
}


/**
 * reverse an IP address for PTR lookup
 * @param address_data IP address to reverse
 * @return NULL on allocation failure
 * @return reversed string on success, caller must free storage via call to free()
 */
char *
reverse_address(struct getdns_bindata *address_data)
{
	ldns_rdf *addr_rdf;
	ldns_rdf *rev_rdf;
	char *rev_str;

	if (address_data->size == 4)
		addr_rdf = ldns_rdf_new(LDNS_RDF_TYPE_A, 4, address_data->data);
	else if (address_data->size == 16)
		addr_rdf = ldns_rdf_new(LDNS_RDF_TYPE_AAAA, 16, address_data->data);
	else
		return NULL;
	if (!addr_rdf)
		return NULL;

	rev_rdf = ldns_rdf_address_reverse(addr_rdf);
	ldns_rdf_free(addr_rdf);
	if (!rev_rdf)
		return NULL;

	rev_str = ldns_rdf2str(rev_rdf);
	ldns_rdf_deep_free(rev_rdf);
	return rev_str;
}

static int
extformatcmp(const void *a, const void *b)
{
	return strcmp(((getdns_extension_format *) a)->extstring,
	    ((getdns_extension_format *) b)->extstring);
}

/*---------------------------------------- validate_extensions */
getdns_return_t
validate_extensions(struct getdns_dict * extensions)
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

			if (item->dtype != extformat->exttype)
				return GETDNS_RETURN_EXTENSION_MISFORMAT;
		}
	return GETDNS_RETURN_GOOD;
}				/* validate_extensions */

getdns_return_t
getdns_apply_network_result(getdns_network_req* netreq,
    struct ub_result* ub_res)
{
	size_t dname_len;

	netreq->secure = ub_res->secure;
	netreq->bogus  = ub_res->bogus;

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

	dname_len = netreq->max_udp_payload_size - GLDNS_HEADER_SIZE;
	if (gldns_str2wire_dname_buf(netreq->owner->name,
	    netreq->response + GLDNS_HEADER_SIZE, &dname_len))
		return GETDNS_RETURN_GENERIC_ERROR;

	gldns_write_uint16( netreq->response + GLDNS_HEADER_SIZE + dname_len
	                  , netreq->request_type);
	gldns_write_uint16( netreq->response + GLDNS_HEADER_SIZE + dname_len + 2
	                  , netreq->request_class);

	netreq->response_len = GLDNS_HEADER_SIZE + dname_len + 4;

	return GETDNS_RETURN_GOOD;
}


getdns_return_t
validate_dname(const char* dname) {
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
} /* validate_dname */


/* util-internal.c */
