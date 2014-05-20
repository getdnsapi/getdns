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

/* create the header dict */
static struct getdns_dict *
create_reply_header_dict(struct getdns_context *context, ldns_pkt * reply)
{
	/* { "id": 23456, "qr": 1, "opcode": 0, ... }, */
	int r = 0;
	struct getdns_dict *result = getdns_dict_create_with_context(context);
	if (!result) {
		return NULL;
	}
	/* cheat since we know GETDNS_RETURN_GOOD == 0 */
    do {
    	r = getdns_dict_set_int(result, GETDNS_STR_KEY_ID,
    	    ldns_pkt_id(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        /* set bits - seems like this could be macro-ified*/
        r = getdns_dict_set_int(result, GETDNS_STR_KEY_QR,
            (int) ldns_pkt_qr(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        r = getdns_dict_set_int(result, GETDNS_STR_KEY_AA,
            (int) ldns_pkt_aa(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        r = getdns_dict_set_int(result, GETDNS_STR_KEY_TC,
            (int) ldns_pkt_tc(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        r = getdns_dict_set_int(result, GETDNS_STR_KEY_RD,
            (int) ldns_pkt_rd(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        r = getdns_dict_set_int(result, GETDNS_STR_KEY_CD,
            (int) ldns_pkt_cd(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        r = getdns_dict_set_int(result, GETDNS_STR_KEY_RA,
            (int) ldns_pkt_ra(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        r = getdns_dict_set_int(result, GETDNS_STR_KEY_AD,
            (int) ldns_pkt_ad(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        /* codes */
        r = getdns_dict_set_int(result, GETDNS_STR_KEY_OPCODE,
            (int) ldns_pkt_get_opcode(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        r = getdns_dict_set_int(result, GETDNS_STR_KEY_RCODE,
            (int) ldns_pkt_get_rcode(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        /* default z to 0 */
        r = getdns_dict_set_int(result, GETDNS_STR_KEY_Z, 0);
        if (r != GETDNS_RETURN_GOOD)
            break;

        /* counts */
        r = getdns_dict_set_int(result, GETDNS_STR_KEY_QDCOUNT,
            (int) ldns_pkt_qdcount(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        r = getdns_dict_set_int(result, GETDNS_STR_KEY_ANCOUNT,
            (int) ldns_pkt_ancount(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        r = getdns_dict_set_int(result, GETDNS_STR_KEY_NSCOUNT,
            (int) ldns_pkt_nscount(reply));
        if (r != GETDNS_RETURN_GOOD)
            break;

        r = getdns_dict_set_int(result, GETDNS_STR_KEY_ARCOUNT,
            (int) ldns_pkt_arcount(reply));
    } while (0);

	if (r != 0) {
		getdns_dict_destroy(result);
		result = NULL;
	}
	return result;
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

static struct getdns_dict *
create_reply_dict(struct getdns_context *context, getdns_network_req * req,
    struct getdns_list * just_addrs)
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
	getdns_return_t r = 0;
	ldns_pkt *reply = NULL;
	ldns_rr_list *rr_list = NULL;
	ldns_rr *question = NULL;
	struct getdns_dict *subdict = NULL;
	struct getdns_list *sublist = NULL;
	char *name = NULL;
        
        if ( req->result == NULL ){
            return NULL;
        }
        reply = req->result;
        
	struct getdns_dict *result = getdns_dict_create_with_context(context);
	if (!result) {
		return NULL;
	}

	/* header */
    do {
    	subdict = create_reply_header_dict(context, reply);
    	r = getdns_dict_set_dict(result, GETDNS_STR_KEY_HEADER, subdict);
    	getdns_dict_destroy(subdict);
        if (r != GETDNS_RETURN_GOOD) {
            break;
        }

    	/* question */
    	r = priv_getdns_create_reply_question_dict(context, reply, &subdict);
        if (r != GETDNS_RETURN_GOOD) {
            break;
        }
    	r = getdns_dict_set_dict(result, GETDNS_STR_KEY_QUESTION, subdict);
    	getdns_dict_destroy(subdict);
        if (r != GETDNS_RETURN_GOOD) {
            break;
        }

    	/* answers */
    	rr_list = ldns_pkt_answer(reply);
    	sublist = create_list_from_rr_list(context, rr_list);

    	r = getdns_dict_set_list(result, GETDNS_STR_KEY_ANSWER, sublist);
    	getdns_list_destroy(sublist);
        if (r != GETDNS_RETURN_GOOD) {
            break;
        }

    	if ((req->request_type == GETDNS_RRTYPE_A ||
    	     req->request_type == GETDNS_RRTYPE_AAAA)) {
    		/* add to just addrs */
    		r = add_only_addresses(just_addrs, rr_list);
            if (r != GETDNS_RETURN_GOOD) {
                break;
            }
    	}

    	/* authority */
    	rr_list = ldns_pkt_authority(reply);
    	sublist = create_list_from_rr_list(context, rr_list);
    	r = getdns_dict_set_list(result, GETDNS_STR_KEY_AUTHORITY, sublist);
    	getdns_list_destroy(sublist);
        if (r != GETDNS_RETURN_GOOD) {
            break;
        }

    	/* additional */
    	rr_list = ldns_pkt_additional(reply);
    	sublist = create_list_from_rr_list(context, rr_list);
        if (sublist) {
            r |= priv_getdns_append_opt_rr(context, sublist, reply);
    	    r |= getdns_dict_set_list(result, GETDNS_STR_KEY_ADDITIONAL, sublist);
        	getdns_list_destroy(sublist);
            if (r != GETDNS_RETURN_GOOD) {
                break;
            }
        }

    	/* other stuff */
    	r = getdns_dict_set_int(result, GETDNS_STR_KEY_ANSWER_TYPE,
    	    GETDNS_NAMETYPE_DNS);
        if (r != GETDNS_RETURN_GOOD) {
            break;
        }
    	question = ldns_rr_list_rr(ldns_pkt_question(reply), 0);
    	name = convert_rdf_to_str(ldns_rr_owner(question));
    	if (! name) {
    		r = GETDNS_RETURN_MEMORY_ERROR;
		break;
	}
    	r = getdns_dict_util_set_string(result,
    	    GETDNS_STR_KEY_CANONICAL_NM, name);
    	free(name);

    } while (0);

	if (r != 0) {
		getdns_dict_destroy(result);
		result = NULL;
	}
	return result;
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
create_getdns_response(struct getdns_dns_req * completed_request)
{
	struct getdns_dict *result = getdns_dict_create_with_context(completed_request->context);
	struct getdns_list *replies_full = getdns_list_create_with_context(
	    completed_request->context);
	struct getdns_list *just_addrs = NULL;
	struct getdns_list *replies_tree = getdns_list_create_with_context(
	    completed_request->context);
	getdns_network_req *netreq;
	char *canonical_name = NULL;
	getdns_return_t r = 0;
	int nreplies = 0, nanswers = 0, nsecure = 0, ninsecure = 0, nbogus = 0;

	/* info (bools) about dns_req */
	int dnssec_return_validation_chain;
	int dnssec_return_only_secure;
	int dnssec_return_status;

	dnssec_return_validation_chain = is_extension_set(
	    completed_request->extensions, "dnssec_return_validation_chain");
	dnssec_return_only_secure = is_extension_set(
	    completed_request->extensions, "dnssec_return_only_secure");
	dnssec_return_status = dnssec_return_only_secure || is_extension_set(
	    completed_request->extensions, "dnssec_return_status") ||
	    completed_request->return_dnssec_status == GETDNS_EXTENSION_TRUE;

	if (completed_request->first_req->request_class == GETDNS_RRTYPE_A ||
	    completed_request->first_req->request_class ==
	    GETDNS_RRTYPE_AAAA) {
		just_addrs = getdns_list_create_with_context(
		    completed_request->context);
	}
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

    	for ( netreq =  completed_request->first_req
	    ; netreq && r == GETDNS_RETURN_GOOD
	    ; netreq = netreq->next ) {

		nreplies++;
		if (netreq->secure)
			nsecure++;
		else if (! netreq->bogus)
			ninsecure++;
		if (dnssec_return_status && netreq->bogus)
			nbogus++;
		else if ((netreq->result != NULL) && (LDNS_RCODE_NOERROR ==
		    ldns_pkt_get_rcode(netreq->result)) )
			nanswers++;

		if (! dnssec_return_validation_chain) {
			if (dnssec_return_status && netreq->bogus)
				continue;
			else if (dnssec_return_only_secure && ! netreq->secure)
				continue;
		}
    		struct getdns_bindata full_data;
    		full_data.data = NULL;
    		full_data.size = 0;
                if (netreq->result != NULL) { 
                    ldns_pkt *pkt = netreq->result;
                    ldns_status s =
                        ldns_pkt2wire(&(full_data.data), pkt, &(full_data.size));
                    if (s != LDNS_STATUS_OK) {
                        // break inner
                        r = GETDNS_RETURN_MEMORY_ERROR;
                        break;
                    }
                }
    		size_t idx = 0;
    		/* reply tree */
    		struct getdns_dict *reply = create_reply_dict(
    		    completed_request->context, netreq, just_addrs);

		if (! reply) {
			r = GETDNS_RETURN_MEMORY_ERROR;
			break;
		}
		if (dnssec_return_status || dnssec_return_validation_chain) {
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
                free(full_data.data);
                // break inner while
                break;
            }
			r = getdns_list_set_bindata(replies_full, idx,
			    &full_data);
			free(full_data.data);
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
	    dnssec_return_only_secure && nsecure == 0 && ninsecure > 0
	                    ? GETDNS_RESPSTATUS_NO_SECURE_ANSWERS :
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
		LDNS_RBTREE_FOR(item, struct getdns_dict_item *,
		    &(extensions->root))
		{
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
    struct ub_result* ub_res) {
    if (ub_res->rcode == 5 ) {
        /* 5==REFUSED so ub_res->answer_packet=NULL, ub_res->answer_len=0 */
        return GETDNS_RETURN_GOOD;
    }
    ldns_status r =
        ldns_wire2pkt(&(netreq->result), ub_res->answer_packet, ub_res->answer_len);
    if (r != LDNS_STATUS_OK) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    netreq->secure = ub_res->secure;
    netreq->bogus  = ub_res->bogus;
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

int
is_extension_set(struct getdns_dict *extensions, const char *extension)
{
	getdns_return_t r;
	uint32_t value;

	if (! extensions)
		return 0;

	r = getdns_dict_get_int(extensions, extension, &value);
        if ( strncmp(extension, "specify_class", 13) == 0 ) {
            /* specify_class is not a boolean */
            return r == GETDNS_RETURN_GOOD;
        } else {
            return r == GETDNS_RETURN_GOOD && value == GETDNS_EXTENSION_TRUE;
        }
}

/* util-internal.c */
