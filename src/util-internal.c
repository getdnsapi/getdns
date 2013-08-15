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

getdns_return_t dict_to_sockaddr(getdns_dict* ns, struct sockaddr_storage* output) {
    struct getdns_bindata *address_type = NULL;
    struct getdns_bindata *address_data = NULL;
    uint16_t port = htons(53);
    memset(output, 0, sizeof(struct sockaddr_storage));
    output->ss_family = AF_UNSPEC;
    
    getdns_dict_get_bindata(ns, GETDNS_STR_ADDRESS_TYPE, &address_type);
    getdns_dict_get_bindata(ns, GETDNS_STR_ADDRESS_DATA, &address_data);
    if (!address_type || !address_data) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    if (strcmp((char*) address_type->data, GETDNS_STR_IPV4)) {
        /* data is an in_addr_t */
        struct sockaddr_in* addr = (struct sockaddr_in*) output;
        addr->sin_family = AF_INET;
        addr->sin_port = port;
        memcpy(&(addr->sin_addr), address_data->data, address_data->size);
    } else {
        /* data is a v6 addr in host order */
        struct sockaddr_in6* addr = (struct sockaddr_in6*) output;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = port;
        memcpy(&(addr->sin6_addr), address_data->data, address_data->size);
    }
    return GETDNS_RETURN_GOOD;
}

/* TODO: flags */
ldns_pkt *create_new_pkt(getdns_context_t context,
                         const char* name,
                         uint16_t request_type,
                         struct getdns_dict* extensions) {
    ldns_pkt *pkt = NULL;
    ldns_rr_type type = (ldns_rr_type) request_type;
    ldns_pkt_query_new_frm_str(&pkt, name,
                               type,
                               LDNS_RR_CLASS_IN, 0);
    if (pkt) {
        /* id */
        ldns_pkt_set_id(pkt, ldns_get_random());
    }
    return pkt;
}



