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
#ifndef _GETDNS_CONTEXT_H_
#define _GETDNS_CONTEXT_H_

#include <getdns/getdns.h>
#include "types-internal.h"

struct getdns_dns_req;
struct ldns_rbtree_t;
struct ub_ctx;

/** function pointer typedefs */
typedef void (*getdns_update_callback) (struct getdns_context *, uint16_t);

struct getdns_context {

	/* Context values */
	uint16_t resolution_type;
	uint16_t *namespaces;
	uint16_t timeout;
	uint16_t follow_redirects;
	struct getdns_list *dns_root_servers;
	uint16_t append_name;
	struct getdns_list *suffix;
	struct getdns_list *dnssec_trust_anchors;
	struct getdns_list *upstream_list;

	uint8_t edns_extended_rcode;
	uint8_t edns_version;
	uint8_t edns_do_bit;

	getdns_update_callback update_callback;

	struct mem_funcs mf;
	struct mem_funcs my_mf;

	/* The underlying unbound contexts that do
	 * the real work */
	struct ub_ctx *unbound_ctx;

	/* which resolution type the contexts are configured for
	 * 0 means nothing set
	 */
	uint8_t resolution_type_set;

	/*
	 * outbound requests -> transaction to getdns_dns_req
	 */
	struct ldns_rbtree_t *outbound_requests;

    /*
     * Event loop extension functions
     * These structs are static and should never be freed
     * since they are just a collection of function pointers
     */
    getdns_eventloop_extension* extension;
    /*
     * Extension data that will be freed by the functions
     * in the extension struct
     */
    void* extension_data;
};

/** internal functions **/
/**
 * Sets up the unbound contexts with stub or recursive behavior
 * if needed.
 */
getdns_return_t getdns_context_prepare_for_resolution(struct getdns_context *context);

/* track an outbound request */
getdns_return_t getdns_context_track_outbound_request(struct getdns_dns_req
    *req);
/* clear the outbound request from being tracked - does not cancel it */
getdns_return_t getdns_context_clear_outbound_request(struct getdns_dns_req
    *req);
/* cancel callback internal - flag to indicate if req should be freed and callback fired */
getdns_return_t getdns_context_cancel_request(struct getdns_context *context,
    getdns_transaction_t transaction_id, int fire_callback);

char *getdns_strdup(const struct mem_funcs *mfs, const char *str);

struct getdns_bindata *getdns_bindata_copy(
    struct mem_funcs *mfs,
    const struct getdns_bindata *src);

void getdns_bindata_destroy(
    struct mem_funcs *mfs,
    struct getdns_bindata *bindata);

/* extension stuff */
getdns_return_t getdns_extension_set_eventloop(struct getdns_context* context,
    getdns_eventloop_extension* extension, void* extension_data);

#endif /* _GETDNS_CONTEXT_H_ */
