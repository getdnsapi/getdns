/**
 *
 * /brief getdns contect management functions
 *
 * This is the meat of the API
 * Originally taken from the getdns API description pseudo implementation.
 *
 */
/* The MIT License (MIT)
 * Copyright (c) 2013 Verisign, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "util-internal.h"
#include "types-internal.h"

getdns_return_t getdns_dict_util_set_string(getdns_dict* dict, char* name,
                                            const char* value) {
    /* account for the null term */
    if (value == NULL) {
        return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
    }
    getdns_bindata type_bin = { strlen(value) + 1, (uint8_t*) value };
    return getdns_dict_set_bindata(dict, name, &type_bin);
}

getdns_return_t getdns_dict_util_get_string(getdns_dict* dict, char* name,
                                            char** result) {
    struct getdns_bindata *bindata = NULL;
    if (!result) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    *result = NULL;
    getdns_dict_get_bindata(dict, name, &bindata);
    if (!bindata) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    *result = (char*) bindata->data;
    return GETDNS_RETURN_GOOD;
}

getdns_return_t dict_to_sockaddr(getdns_dict* ns, struct sockaddr_storage* output) {
    char* address_type = NULL;
    struct getdns_bindata *address_data = NULL;
    uint32_t port = 53;
    memset(output, 0, sizeof(struct sockaddr_storage));
    output->ss_family = AF_UNSPEC;

    uint32_t prt = 0;
    if (getdns_dict_get_int(ns, GETDNS_STR_PORT, &prt) == GETDNS_RETURN_GOOD) {
        port = prt;
    }

    getdns_dict_util_get_string(ns, GETDNS_STR_ADDRESS_TYPE, &address_type);
    getdns_dict_get_bindata(ns, GETDNS_STR_ADDRESS_DATA, &address_data);
    if (!address_type || !address_data) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    if (strncmp(GETDNS_STR_IPV4, address_type, strlen(GETDNS_STR_IPV4)) == 0) {
        /* data is an in_addr_t */
        struct sockaddr_in* addr = (struct sockaddr_in*) output;
        addr->sin_family = AF_INET;
        addr->sin_port = htons((uint16_t)port);
        memcpy(&(addr->sin_addr), address_data->data, address_data->size);
    } else {
        /* data is a v6 addr in host order */
        struct sockaddr_in6* addr = (struct sockaddr_in6*) output;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons((uint16_t)port);
        memcpy(&(addr->sin6_addr), address_data->data, address_data->size);
    }
    return GETDNS_RETURN_GOOD;
}

getdns_return_t sockaddr_to_dict(struct sockaddr_storage* address, getdns_dict** output) {
    if (!output || !address) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    getdns_bindata addr_data;
    *output = NULL;
    getdns_dict* result = getdns_dict_create();
    if (address->ss_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*) address;
        getdns_dict_util_set_string(result, GETDNS_STR_ADDRESS_TYPE, GETDNS_STR_IPV4);
        addr_data.size = sizeof(addr->sin_addr);
        addr_data.data = (uint8_t*) &(addr->sin_addr);
        getdns_dict_set_bindata(result, GETDNS_STR_ADDRESS_DATA, &addr_data);
    } else if (address->ss_family == AF_INET6) {
        struct sockaddr_in6* addr = (struct sockaddr_in6*) address;
        getdns_dict_util_set_string(result, GETDNS_STR_ADDRESS_TYPE, GETDNS_STR_IPV6);
        addr_data.size = sizeof(addr->sin6_addr);
        addr_data.data = (uint8_t*) &(addr->sin6_addr);
        getdns_dict_set_bindata(result, GETDNS_STR_ADDRESS_DATA, &addr_data);
    } else {
        // invalid
        getdns_dict_destroy(result);
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    *output = result;
    return GETDNS_RETURN_GOOD;
}

/* result must be freed */
static char* convert_rdf_to_str(ldns_rdf* rdf) {
    if (ldns_rdf_get_type(rdf) == LDNS_RDF_TYPE_DNAME) {
        ldns_dname2canonical(rdf);
    }
    return ldns_rdf2str(rdf);
}

/* create the header dict */
static getdns_dict *create_reply_header_dict(ldns_pkt* reply) {
    /* { "id": 23456, "qr": 1, "opcode": 0, ... }, */
    int r = 0;
    getdns_dict* result = getdns_dict_create();
    if (!result) {
        return NULL;
    }
    /* cheat since we know GETDNS_RETURN_GOOD == 0 */
    r |= getdns_dict_set_int(result, GETDNS_STR_KEY_ID, ldns_pkt_id(reply));
    r |= getdns_dict_set_int(result, GETDNS_STR_KEY_QR, ldns_pkt_qr(reply));
    r |= getdns_dict_set_int(result, GETDNS_STR_KEY_OPC, (int) ldns_pkt_get_opcode(reply));

    if (r != 0) {
        getdns_dict_destroy(result);
        result = NULL;
    }
    return result;
}

static getdns_dict *create_reply_question_dict(ldns_pkt* reply) {
    /* { "qname": <bindata for "www.example.com">, "qtype": 1, "qclass": 1 } */
    int r = 0;
    ldns_rr *question = NULL;
    char* qname;
    getdns_dict* result = getdns_dict_create();
    if (!result) {
        return NULL;
    }
    question = ldns_rr_list_rr(ldns_pkt_question(reply), 0);
    r |= getdns_dict_set_int(result, GETDNS_STR_KEY_QTYPE, (int) ldns_rr_get_type(question));
    r |= getdns_dict_set_int(result, GETDNS_STR_KEY_QCLASS, (int) ldns_rr_get_class(question));
    qname = convert_rdf_to_str(ldns_rr_owner(question));
    if (qname) {
        r |= getdns_dict_util_set_string(result, GETDNS_STR_KEY_QNAME, qname);
        free(qname);
    } else {
        r = 1;
    }
    if (r != 0) {
        getdns_dict_destroy(result);
        result = NULL;
    }
    return result;
}

static getdns_dict *create_dict_from_rdf(ldns_rdf* rdf) {
    /*
    create a dict w/ rdata_raw and special fields if needed
    i.e.
    {
      "ipv4_address": <bindata of 0x0a0b0c01>
      "rdata_raw": <bindata of 0x0a0b0c01>
    }
    */
    int r = 0;
    getdns_bindata rbin = { ldns_rdf_size(rdf), ldns_rdf_data(rdf) };
    getdns_dict* result = getdns_dict_create();
    r |= getdns_dict_set_bindata(result, GETDNS_STR_KEY_RDATA_RAW, &rbin);
    if (ldns_rdf_get_type(rdf) == LDNS_RDF_TYPE_AAAA) {
        r |= getdns_dict_set_bindata(result, GETDNS_STR_KEY_V6_ADDR, &rbin);
    } else if (ldns_rdf_get_type(rdf) == LDNS_RDF_TYPE_A) {
        r |= getdns_dict_set_bindata(result, GETDNS_STR_KEY_V4_ADDR, &rbin);
    }
    if (r != 0) {
        getdns_dict_destroy(result);
        result = NULL;
    }
    return result;
}

static getdns_dict *create_dict_from_rr(ldns_rr* rr) {
    /*
    {
      "name": <bindata for "www.example.com">,
      "type": 1,
      "class": 1,
      "ttl": 33000,
      "rdata":
      {
        "ipv4_address": <bindata of 0x0a0b0c01>
        "rdata_raw": <bindata of 0x0a0b0c01>
      }
    }
    */
    int r = 0;
    char * name = NULL;
    getdns_dict *result = getdns_dict_create();
    size_t rd_count = ldns_rr_rd_count(rr);
    ldns_rdf* owner = ldns_rr_owner(rr);
    r |= getdns_dict_set_int(result, GETDNS_STR_KEY_TYPE, (int) ldns_rr_get_type(rr));
    r |= getdns_dict_set_int(result, GETDNS_STR_KEY_CLASS, (int) ldns_rr_get_class(rr));
    r |= getdns_dict_set_int(result, GETDNS_STR_KEY_TTL, ldns_rr_ttl(rr));
    if (owner) {
        name = convert_rdf_to_str(owner);
        if (name) {
            r |= getdns_dict_util_set_string(result, GETDNS_STR_KEY_NAME, name);
            free(name);
        } else {
            r = 1;
        }
    }
    /* create rdatas */
    if (rd_count >= 1) {
        getdns_dict* rdata = create_dict_from_rdf(ldns_rr_rdf(rr, 0));
        r |= getdns_dict_set_dict(result, GETDNS_STR_KEY_RDATA, rdata);
    }
    /* TODO - if more than one, is rdata a list? */

    if (r != 0) {
        getdns_dict_destroy(result);
        result = NULL;
    }
    return result;
}

/* helper to convert an rr_list to getdns_list.
   returns a list of objects where each object
   is a result from create_dict_from_rr */
static getdns_list *create_list_from_rr_list(ldns_rr_list* rr_list) {
    size_t i = 0;
    size_t idx = 0;
    int r = 0;
    getdns_list *result = getdns_list_create();
    for (i = 0; i < ldns_rr_list_rr_count(rr_list); ++i) {
        ldns_rr *rr = ldns_rr_list_rr(rr_list, i);
        r |= getdns_list_add_item(result, &idx);
        r |= getdns_list_set_dict(result, idx, create_dict_from_rr(rr));
    }
    if (r != 0) {
        getdns_list_destroy(result);
        result = NULL;
    }
    return result;
}

/* helper to add the ipv4 or ipv6 bin data to the list of addrs */
static getdns_return_t add_only_addresses(getdns_list* addrs, ldns_rr_list* rr_list) {
    int r = 0;
    size_t i = 0;
    for (i = 0; i < ldns_rr_list_rr_count(rr_list); ++i) {
        ldns_rr *rr = ldns_rr_list_rr(rr_list, i);
        size_t j = 0;
        size_t rd_count = ldns_rr_rd_count(rr);
        for (j = 0; j < rd_count; ++j) {
            size_t item_idx = 0;
            ldns_rdf* rdf = ldns_rr_rdf(rr, j);
            getdns_bindata rbin = { ldns_rdf_size(rdf), ldns_rdf_data(rdf) };
            r |= getdns_list_add_item(addrs, &item_idx);
            r |= getdns_list_set_bindata(addrs, item_idx, &rbin);
        }
    }
    return r;
}

static getdns_dict *create_reply_dict(getdns_network_req* req,
                                      getdns_list *just_addrs) {
    /* turn a packet into this glorious structure

    {     # This is the first reply
      "header": { "id": 23456, "qr": 1, "opcode": 0, ... },
      "question": { "qname": <bindata for "www.example.com">, "qtype": 1, "qclass": 1 },
      "answer":
      [
        {
          "name": <bindata for "www.example.com">,
          "type": 1,
          "class": 1,
          "ttl": 33000,
          "rdata":
          {
            "ipv4_address": <bindata of 0x0a0b0c01>
            "rdata_raw": <bindata of 0x0a0b0c01>
          }
        }
      ],
      "authority":
      [
        {
          "name": <bindata for "ns1.example.com">,
          "type": 1,
          "class": 1,
          "ttl": 600,
          "rdata":
          {
            "ipv4_address": <bindata of 0x65439876>
            "rdata_raw": <bindata of 0x65439876>
          }
        }
      ]
      "additional": [],
      "canonical_name": <bindata for "www.example.com">,
      "answer_type": GETDNS_NAMETYPE_DNS
    }

    */
    int r = 0;
    ldns_pkt *reply = req->result;
    ldns_rr_list *rr_list = NULL;
    ldns_rr* question = NULL;
    getdns_dict *subdict = NULL;
    getdns_list *sublist = NULL;
    char* name = NULL;

    getdns_dict *result = getdns_dict_create();
    if (!result) {
        return NULL;
    }
    /* header */
    subdict = create_reply_header_dict(reply);
    r |= getdns_dict_set_dict(result, GETDNS_STR_KEY_HEADER, subdict);
    getdns_dict_destroy(subdict);

    /* question */
    subdict = create_reply_question_dict(reply);
    r |= getdns_dict_set_dict(result, GETDNS_STR_KEY_QUESTION, subdict);
    getdns_dict_destroy(subdict);

    /* answers */
    rr_list = ldns_pkt_answer(reply);
    sublist = create_list_from_rr_list(rr_list);
    r |= getdns_dict_set_list(result, GETDNS_STR_KEY_ANSWER, sublist);
    getdns_list_destroy(sublist);
    if ((req->request_type == GETDNS_RRTYPE_A ||
        req->request_type == GETDNS_RRTYPE_AAAA) &&
        just_addrs != NULL) {
        /* add to just addrs */
        r |= add_only_addresses(just_addrs, rr_list);
    }

    /* authority */
    rr_list = ldns_pkt_authority(reply);
    sublist = create_list_from_rr_list(rr_list);
    r |= getdns_dict_set_list(result, GETDNS_STR_KEY_AUTHORITY, sublist);
    getdns_list_destroy(sublist);

    /* additional */
    rr_list = ldns_pkt_additional(reply);
    sublist = create_list_from_rr_list(rr_list);
    r |= getdns_dict_set_list(result, GETDNS_STR_KEY_ADDITIONAL, sublist);
    getdns_list_destroy(sublist);

    /* other stuff */
    r |= getdns_dict_set_int(result, GETDNS_STR_KEY_ANSWER_TYPE, GETDNS_NAMETYPE_DNS);
    question = ldns_rr_list_rr(ldns_pkt_question(reply), 0);
    name = convert_rdf_to_str(ldns_rr_owner(question));
    if (name) {
        r |= getdns_dict_util_set_string(result, GETDNS_STR_KEY_CANONICAL_NM, name);
        free(name);
    } else {
        r |= 1;
    }
    if (r != 0) {
        getdns_dict_destroy(result);
        result = NULL;
    }
    return result;
}

static char* get_canonical_name(const char* name) {
    ldns_rdf* rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, name);
    if (!rdf) {
        return NULL;
    }
    char* result = convert_rdf_to_str(rdf);
    ldns_rdf_free(rdf);
    return result;
}

getdns_dict *create_getdns_response(struct getdns_dns_req* completed_request) {
    getdns_dict* result = getdns_dict_create();
    getdns_list* replies_full = getdns_list_create();
    getdns_list* just_addrs = NULL;
    getdns_list* replies_tree = getdns_list_create();
    getdns_network_req *netreq = completed_request->first_req;


    int r = 0;

    if (completed_request->first_req->request_class == GETDNS_RRTYPE_A ||
        completed_request->first_req->request_class ==  GETDNS_RRTYPE_AAAA) {
        just_addrs = getdns_list_create();
    }

    r |= getdns_dict_set_int(result, GETDNS_STR_KEY_STATUS, GETDNS_RESPSTATUS_GOOD);
    r |= getdns_dict_util_set_string(result, GETDNS_STR_KEY_CANONICAL_NM, get_canonical_name(completed_request->name));
    r |= getdns_dict_set_int(result, GETDNS_STR_KEY_ANSWER_TYPE, GETDNS_NAMETYPE_DNS);

    while (netreq) {
        getdns_bindata full_data;
        full_data.data = NULL;
        full_data.size = 0;
        ldns_pkt *pkt = netreq->result;
        ldns_status s = ldns_pkt2wire(&(full_data.data), pkt, &(full_data.size));
        size_t idx = 0;
        /* reply tree */
        getdns_dict *reply = create_reply_dict(netreq, just_addrs);
        r |= getdns_list_add_item(replies_tree, &idx);
        r |= getdns_list_set_dict(replies_tree, idx, reply);
        /* buffer */
        if (s == LDNS_STATUS_OK) {
            r |= getdns_list_add_item(replies_full, &idx);
            r |= getdns_list_set_bindata(replies_full, idx, &full_data);
            free(full_data.data);
        } else {
            r = 1;
            break;
        }
        netreq = netreq->next;
    }

    r |= getdns_dict_set_list(result, GETDNS_STR_KEY_REPLIES_TREE, replies_tree);
    r |= getdns_dict_set_list(result, GETDNS_STR_KEY_REPLIES_FULL, replies_full);
    if (just_addrs) {
        r |= getdns_dict_set_list(result, GETDNS_STR_KEY_JUST_ADDRS, just_addrs);
    }

    if (r != 0) {
        getdns_dict_destroy(result);
        result = NULL;
    }

    return result;
}

