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
	uint32_t ttl; /* todo: should this be an expiration date? */
	uint8_t * record_data;
	int record_length;
} getdns_mdns_known_record;

typedef struct getdns_mdns_continuous_query
{
	uint8_t name[256]; /* binary representation of name being queried */
	int name_len;
	uint16_t request_class;
	uint16_t request_type;
	/* list of known records */
	_getdns_rbtree_t known_records_by_value;
	/* list of user queries */
	_getdns_rbtree_t netreq_by_query_id;
	/* todo: do we need an expiration date, or a timer? */
	/* todo: do we need an update mark for showing last results? */
} getdns_mdns_continuous_query;


#endif /* HAVE_MDNS_SUPPORT */

#endif /* MDNS_H */
