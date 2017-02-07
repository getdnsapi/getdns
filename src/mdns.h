/*
* Functions for MDNS resolving.
*/

/*
* Copyright (c) 2016 Christian Huitema <huitema@huitema.net>
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#ifndef MDNS_H
#define MDNS_H

#ifdef HAVE_MDNS_SUPPORT
#include "getdns/getdns.h"
#include "types-internal.h"

getdns_return_t
_getdns_submit_mdns_request(getdns_network_req *netreq);

getdns_return_t
_getdns_mdns_namespace_check(getdns_dns_req *dnsreq);

/*
 * data structure for continuous queries
 */

typedef struct getdns_mdns_known_record
{
	/* For storage in context->mdns_known_records_by_value */
	_getdns_rbnode_t node;
	uint64_t insertion_microsec;
	uint16_t request_type;
	uint16_t request_class;
	uint32_t ttl;
	int name_len;
	int record_len;
	uint8_t* name;
	uint8_t * record_data;
} getdns_mdns_known_record;

typedef struct getdns_mdns_continuous_query
{
	/* For storage in context->mdns_continuous_queries_by_name_rrtype */
	_getdns_rbnode_t node;
	uint8_t name[256]; /* binary representation of name being queried */
	int name_len;
	uint16_t request_class;
	uint16_t request_type;
	/* list of user queries */
	getdns_network_req *netreq_first;
	/* todo: do we need an expiration date, or a timer? */
	/* todo: do we need an update mark for showing last results? */
} getdns_mdns_continuous_query;


void _getdns_mdns_context_init(struct getdns_context *context);
void _getdns_mdns_context_destroy(struct getdns_context *context);

#endif /* HAVE_MDNS_SUPPORT */

#endif /* MDNS_H */
