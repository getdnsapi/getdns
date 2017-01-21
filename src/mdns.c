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


#include "config.h"
#include "debug.h"
#include "context.h"
#include "general.h"
#include "gldns/pkthdr.h"
#include "util-internal.h"
#include "mdns.h"

#ifdef HAVE_MDNS_SUPPORT

#ifdef USE_WINSOCK
typedef u_short sa_family_t;
#define _getdns_EWOULDBLOCK (WSAGetLastError() == WSATRY_AGAIN ||\
                             WSAGetLastError() == WSAEWOULDBLOCK)
#define _getdns_EINPROGRESS (WSAGetLastError() == WSAEINPROGRESS)
#else
#define _getdns_EWOULDBLOCK (errno == EAGAIN || errno == EWOULDBLOCK)
#define _getdns_EINPROGRESS (errno == EINPROGRESS)
#endif

uint64_t _getdns_get_time_as_uintt64();

/*
 * Constants defined in RFC 6762
 */

#define MDNS_MCAST_IPV4_LONG 0xE00000FB /* 224.0.0.251 */
#define MDNS_MCAST_PORT 5353

/*
 * TODO: When we start supporting IPv6 with MDNS, need to define this:
 * static uint8_t mdns_mcast_ipv6[] = { 
 *	0xFF, 0x02, 0, 0, 0, 0, 0, 0,
 *	0, 0, 0, 0, 0, 0, 0, 0xFB };
 */

static uint8_t mdns_suffix_dot_local[] = { 5, 'l', 'o', 'c', 'a', 'l', 0 };
static uint8_t mdns_suffix_254_169_in_addr_arpa[] = {
	3, '2', '5', '4',
	3, '1', '6', '9',
	7, 'i', 'n', '-', 'a', 'd', 'd', 'r',
	4, 'a', 'r', 'p', 'a', 0 };
static uint8_t mdns_suffix_8_e_f_ip6_arpa[] = {
	1, '8', 1, 'e', 1, 'f',
	7, 'i', 'p', 'v', '6',
	4, 'a', 'r', 'p', 'a', 0 };
static uint8_t mdns_suffix_9_e_f_ip6_arpa[] = {
	1, '9', 1, 'e', 1, 'f',
	7, 'i', 'p', 'v', '6',
	4, 'a', 'r', 'p', 'a', 0 };
static uint8_t mdns_suffix_a_e_f_ip6_arpa[] = {
	1, 'a', 1, 'e', 1, 'f',
	7, 'i', 'p', 'v', '6',
	4, 'a', 'r', 'p', 'a', 0 };
static uint8_t mdns_suffix_b_e_f_ip6_arpa[] = {
	1, 'b', 1, 'e', 1, 'f',
	7, 'i', 'p', 'v', '6',
	4, 'a', 'r', 'p', 'a', 0 };


/*
* Compare function for the netreq_by_query_id,
* used in the red-black tree of all netreq by continuous query.
*/
static int mdns_cmp_netreq_by_query_id(const void * id1, const void * id2)
{
	int ret = 0;

	if (id1 != id2)
	{
		ret = (((intptr_t)id1) < ((intptr_t)id2)) ? -1 : 1;
	}
	return ret;
}

/*
 * Compare function for the getdns_mdns_known_record type,
 * used in the red-black tree of known records per query.
 */

static int mdns_cmp_known_records(const void * nkr1, const void * nkr2)
{
	int ret = 0;
	getdns_mdns_known_record * kr1 = (getdns_mdns_known_record *)nkr1;
	getdns_mdns_known_record * kr2 = (getdns_mdns_known_record *)nkr2;

	if (kr1->record_length != kr2->record_length)
	{
		ret = (kr1->record_length < kr2->record_length) ? -1 : 1;
	}
	else
	{
		ret = memcmp((const void*)kr1->record_data, (const void*)kr2->record_data, kr1->record_length);
	}

	return ret;
}

/*
 * Compare function for the mdns_continuous_query_by_name_rrtype,
 * used in the red-black tree of all ongoing queries.
 */
static int mdns_cmp_continuous_queries_by_name_rrtype(const void * nqnr1, const void * nqnr2)
{
	int ret = 0;
	getdns_mdns_continuous_query * qnr1 = (getdns_mdns_continuous_query *)nqnr1;
	getdns_mdns_continuous_query * qnr2 = (getdns_mdns_continuous_query *)nqnr2;

	if (qnr1->request_class != qnr2->request_class) 
	{
		ret = (qnr1->request_class < qnr2->request_class) ? -1 : 1;
	} 
	else if (qnr1->request_type != qnr2->request_type)
	{
		ret = (qnr1->request_type < qnr2->request_type) ? -1 : 1;
	}
	else if (qnr1->name_len != qnr2->name_len)
	{
		ret = (qnr1->name_len < qnr2->name_len) ? -1 : 1;
	}
	else
	{
		ret = memcmp((void*)qnr1->name, (void*)qnr2->name, qnr1->name_len);
	}
	return ret;
}

/*
 * Initialize a continuous query from netreq
 */
static int mdns_initialize_continuous_request(getdns_network_req *netreq)
{
	int ret = 0;
	getdns_mdns_continuous_query temp_query, *continuous_query, *inserted_query;
	getdns_dns_req *dnsreq = netreq->owner;
	/*
	 * Fill the target request, but only initialize name and request_type
	 */
	temp_query.request_class = dnsreq->request_class;
	temp_query.request_type = netreq->request_type;
	temp_query.name_len = dnsreq->name_len;
	/* TODO: check that dnsreq is in canonical form */
	memcpy(temp_query.name, dnsreq->name, dnsreq->name_len);
	/*
	 * Check whether the continuous query is already in the RB tree.
	 * if there is not, create one.
	 * TODO: should lock the context object when doing that.
	 */
	continuous_query = (getdns_mdns_continuous_query *)
		_getdns_rbtree_search(&dnsreq->context->mdns_continuous_queries_by_name_rrtype, &temp_query);
	if (continuous_query == NULL)
	{
		continuous_query = (getdns_mdns_continuous_query *)
			GETDNS_MALLOC(dnsreq->context->mf, getdns_mdns_continuous_query);
		if (continuous_query != NULL)
		{
			continuous_query->request_class = temp_query.request_class;
			continuous_query->request_type = temp_query.request_type;
			continuous_query->name_len = temp_query.name_len;
			memcpy(continuous_query->name, temp_query.name, temp_query.name_len);
			_getdns_rbtree_init(&continuous_query->known_records_by_value, mdns_cmp_known_records);
			/* Tracking of network requests on this socket */
			_getdns_rbtree_init(&continuous_query->netreq_by_query_id, mdns_cmp_netreq_by_query_id);
			/* Add the new continuous query to the context */
			inserted_query = _getdns_rbtree_insert(&dnsreq->context->mdns_continuous_queries_by_name_rrtype,
				continuous_query);
			if (inserted_query == NULL)
			{
				/* Weird. This can only happen in a race condition */
				GETDNS_FREE(dnsreq->context->mf, continuous_query);
				ret = GETDNS_RETURN_GENERIC_ERROR;
			}
		}
		else
		{
			ret = GETDNS_RETURN_MEMORY_ERROR;
		}
	}
	/* To do: insert netreq into query list */
	/* to do: queue message request to socket */

	return ret;
}

/* TODO: actualy delete what is required.. */
static void
mdns_cleanup(getdns_network_req *netreq)
{
	DEBUG_MDNS("%s %-35s: MSG: %p\n",
		MDNS_DEBUG_CLEANUP, __FUNCTION__, netreq);
	getdns_dns_req *dnsreq = netreq->owner;

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	GETDNS_NULL_FREE(dnsreq->context->mf, netreq->tcp.read_buf);
}

void
_getdns_cancel_mdns_request(getdns_network_req *netreq)
{
	mdns_cleanup(netreq);
	if (netreq->fd >= 0) {
#ifdef USE_WINSOCK
		closesocket(netreq->fd);
#else
		close(netreq->fd);
#endif
	}
}

static void
mdns_timeout_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	DEBUG_MDNS("%s %-35s: MSG:  %p\n",
		MDNS_DEBUG_CLEANUP, __FUNCTION__, netreq);

	/* TODO: do we need a retry logic here? */

	/* Check the required cleanup */
	mdns_cleanup(netreq);
	if (netreq->fd >= 0)
#ifdef USE_WINSOCK
		closesocket(netreq->fd);
#else
		close(netreq->fd);
#endif
	netreq->state = NET_REQ_TIMED_OUT;
	if (netreq->owner->user_callback) {
		netreq->debug_end_time = _getdns_get_time_as_uintt64();
		(void)_getdns_context_request_timed_out(netreq->owner);
	}
	else
		_getdns_check_dns_req_complete(netreq->owner);
}



/**************************/
/* UDP callback functions */
/**************************/

static void
mdns_udp_read_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req *dnsreq = netreq->owner;
	ssize_t       read;
	DEBUG_MDNS("%s %-35s: MSG: %p \n", MDNS_DEBUG_READ,
		__FUNCTION__, netreq);

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	read = recvfrom(netreq->fd, (void *)netreq->response,
		netreq->max_udp_payload_size + 1, /* If read == max_udp_payload_size
										  * then all is good.  If read ==
										  * max_udp_payload_size + 1, then
										  * we receive more then requested!
										  * i.e. overflow
										  */
		0, NULL, NULL);
	if (read == -1 && _getdns_EWOULDBLOCK)
		return;

	if (read < GLDNS_HEADER_SIZE)
		return; /* Not DNS */

	if (GLDNS_ID_WIRE(netreq->response) != netreq->query_id)
		return; /* Cache poisoning attempt ;) */

	// TODO: check whether EDNS server cookies are required for MDNS

	// TODO: check that the source address originates from the local network.
	// TODO: check TTL = 255

#ifdef USE_WINSOCK
	closesocket(netreq->fd);
#else
	close(netreq->fd);
#endif
	/* 
	 * TODO: how to handle an MDNS response with TC bit set?
	 * Ignore it for now, as we do not support any kind of TCP fallback
	 * for basic MDNS.
	 */
	
	netreq->response_len = read;
	netreq->debug_end_time = _getdns_get_time_as_uintt64();
	netreq->state = NET_REQ_FINISHED;
	_getdns_check_dns_req_complete(dnsreq);
}

static void
mdns_udp_write_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	getdns_dns_req     *dnsreq = netreq->owner;
	size_t             pkt_len = netreq->response - netreq->query;
	struct sockaddr_in mdns_mcast_v4;
	int	ttl = 255;
	int r;

	DEBUG_MDNS("%s %-35s: MSG: %p \n", MDNS_DEBUG_WRITE,
		__FUNCTION__, netreq);

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	netreq->debug_start_time = _getdns_get_time_as_uintt64();
	netreq->debug_udp = 1;
	netreq->query_id = (uint16_t) arc4random();
	GLDNS_ID_SET(netreq->query, netreq->query_id);

	/* do we need to handle options valid in the MDNS context? */

	/* Probably no need for TSIG in MDNS */


	/* Always use multicast address */
	mdns_mcast_v4.sin_family = AF_INET;
	mdns_mcast_v4.sin_port = htons(MDNS_MCAST_PORT);
	mdns_mcast_v4.sin_addr.s_addr = htonl(MDNS_MCAST_IPV4_LONG);


	/* Set TTL=255 for compliance with RFC 6762 */
	r = setsockopt(netreq->fd, IPPROTO_IP, IP_TTL, (const char *)&ttl, sizeof(ttl));

	if (r != 0 || 
		(ssize_t)pkt_len != sendto(
		netreq->fd, (const void *)netreq->query, pkt_len, 0,
		(struct sockaddr *)&mdns_mcast_v4,
		sizeof(mdns_mcast_v4))) {
#ifdef USE_WINSOCK
		closesocket(netreq->fd);
#else
		close(netreq->fd);
#endif
		return;
	}
	GETDNS_SCHEDULE_EVENT(
		dnsreq->loop, netreq->fd, dnsreq->context->timeout,
		getdns_eventloop_event_init(&netreq->event, netreq,
			mdns_udp_read_cb, NULL, mdns_timeout_cb));
}

/*
 * MDNS Request Submission
 */

getdns_return_t
_getdns_submit_mdns_request(getdns_network_req *netreq)
{
	DEBUG_MDNS("%s %-35s: MSG: %p TYPE: %d\n", MDNS_DEBUG_ENTRY, __FUNCTION__,
		netreq, netreq->request_type);
	int fd = -1;
	getdns_dns_req *dnsreq = netreq->owner;

	/* Open the UDP socket required for the request */
	if ((fd = socket(
		AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		return -1;
	/* TODO: do we need getdns_sock_nonblock(fd); */

	/* Schedule the MDNS request */
	netreq->fd = fd;
	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
	GETDNS_SCHEDULE_EVENT(
		dnsreq->loop, netreq->fd, dnsreq->context->timeout,
		getdns_eventloop_event_init(&netreq->event, netreq,
			NULL, mdns_udp_write_cb, mdns_timeout_cb));
	return GETDNS_RETURN_GOOD;
}

/*
 * MDNS name space management
 */

static int
mdns_suffix_compare(register const uint8_t *d1, register const uint8_t *d2)
{
	int ret = 0;
	uint8_t *d1_head = (uint8_t *) d1;
	uint8_t *d1_current;
	uint8_t *d2_current;
	int is_matching = 0;
	int part_length;
	int i;
	uint8_t c;

	/* Skip the first name part, since we want at least one label before the suffix */
	if (*d1_head != 0)
		d1_head += *d1_head + 1;

	while (*d1_head != 0)
	{
		/* check whether we have a match at this point */
		d1_current = d1_head;
		d2_current = (uint8_t *) d2;
		is_matching = 0;

		/* compare length and value of all successive labels */
		while (*d1_current == *d2_current)
		{
			part_length = *d1_current;
			if (part_length == 0)
			{
				/* We have reached the top label, there is a match */
				ret = 1;
				break;
			}

			/* The label's lengths are matching, check the content */
			is_matching = 1;
			d1_current++;
			d2_current++;

			for (i = 0; i < part_length; i++)
			{
				c = d1_current[i];
				if (isupper(c))
					c = tolower(c);
				if (c != d2_current[i])
				{
					is_matching = 0;
					break;
				}
			}
			
			/* move the pointers to the next label */
			if (is_matching)
			{
				d1_current += part_length;
				d2_current += part_length;
			}
		}

		/* if no match found yet, move to the next label of d1 */
		if (is_matching)
			break;
		else
			d1_head += *d1_head + 1;
	}

	return ret;
}


getdns_return_t
_getdns_mdns_namespace_check(
	getdns_dns_req *dnsreq)
{
	getdns_return_t ret = GETDNS_RETURN_GENERIC_ERROR;

	/* Checking the prefixes defined in RFC 6762  */
	if (mdns_suffix_compare(dnsreq->name, mdns_suffix_dot_local) ||
		mdns_suffix_compare(dnsreq->name, mdns_suffix_254_169_in_addr_arpa) ||
		mdns_suffix_compare(dnsreq->name, mdns_suffix_8_e_f_ip6_arpa) ||
		mdns_suffix_compare(dnsreq->name, mdns_suffix_9_e_f_ip6_arpa) ||
		mdns_suffix_compare(dnsreq->name, mdns_suffix_a_e_f_ip6_arpa) ||
		mdns_suffix_compare(dnsreq->name, mdns_suffix_b_e_f_ip6_arpa))
		ret = GETDNS_RETURN_GOOD;

	return ret;
}

#endif /* HAVE_MDNS_SUPPORT */
