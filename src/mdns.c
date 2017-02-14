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

#include "util/storage/lruhash.h"
#include "util/storage/lookup3.h"

#ifndef HAVE_LIBUNBOUND
#include "util/storage/lruhash.c"
#include "util/storage/lookup3.c"
#endif

/*
 * Constants defined in RFC 6762
 */

#define MDNS_MCAST_IPV4_LONG 0xE00000FB /* 224.0.0.251 */
#define MDNS_MCAST_PORT 5353

static uint8_t mdns_mcast_ipv6[] = {
	0xFF, 0x02, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0xFB 
};

static uint8_t mdns_suffix_dot_local[] = { 5, 'l', 'o', 'c', 'a', 'l', 0 };
static uint8_t mdns_suffix_254_169_in_addr_arpa[] = {
	3, '2', '5', '4',
	3, '1', '6', '9',
	7, 'i', 'n', '-', 'a', 'd', 'd', 'r',
	4, 'a', 'r', 'p', 'a', 0 };
static uint8_t mdns_suffix_8_e_f_ip6_arpa[] = {
	1, '8', 1, 'e', 1, 'f',
	3, 'i', 'p', '6',
	4, 'a', 'r', 'p', 'a', 0 };
static uint8_t mdns_suffix_9_e_f_ip6_arpa[] = {
	1, '9', 1, 'e', 1, 'f',
	3, 'i', 'p', '6',
	4, 'a', 'r', 'p', 'a', 0 };
static uint8_t mdns_suffix_a_e_f_ip6_arpa[] = {
	1, 'a', 1, 'e', 1, 'f',
	3, 'i', 'p', '6',
	4, 'a', 'r', 'p', 'a', 0 };
static uint8_t mdns_suffix_b_e_f_ip6_arpa[] = {
	1, 'b', 1, 'e', 1, 'f',
	3, 'i', 'p', '6',
	4, 'a', 'r', 'p', 'a', 0 };

/*
 * MDNS cache management using LRU Hash.
 *
 * Each record contains a DNS query + response, formatted as received from
 * the network. By convention, there will be exactly one query, and
 * a variable number of answers. Auth and AD sections will not be cached.
 * For maintenance purpose, each recontains a last accessed time stamp.
 *
 * This structure works very well for classic DNS caches, but for MDNS we 
 * have to consider processing a new record for an existing cache entry. If
 * the record is present, its TTL should be updated. If the record is not
 * present, it should be added to the existing data.
 *
 * After an update, the TTL of all the records should be updated. Some
 * records will end up with a TTL value of zero. These records should be 
 * deleted, using a "compression" procedure.
 */

/*
 * Missing LRU hash function: create only if not currently in cache,
 * and return the created or found entry.
 *
 * TODO: move this to lruhash.c, once source control issues are fixed.
 */
static struct lruhash_entry*
lruhash_insert_or_retrieve(struct lruhash* table, hashvalue_type hash,
struct lruhash_entry* entry, void* data, void* cb_arg)
{
	struct lruhash_bin* bin;
	struct lruhash_entry* found, *reclaimlist = NULL;
	size_t need_size;
	fptr_ok(fptr_whitelist_hash_sizefunc(table->sizefunc));
	fptr_ok(fptr_whitelist_hash_delkeyfunc(table->delkeyfunc));
	fptr_ok(fptr_whitelist_hash_deldatafunc(table->deldatafunc));
	fptr_ok(fptr_whitelist_hash_compfunc(table->compfunc));
	fptr_ok(fptr_whitelist_hash_markdelfunc(table->markdelfunc));
	need_size = table->sizefunc(entry->key, data);
	if (cb_arg == NULL) cb_arg = table->cb_arg;

	/* find bin */
	lock_quick_lock(&table->lock);
	bin = &table->array[hash & table->size_mask];
	lock_quick_lock(&bin->lock);

	/* see if entry exists already */
	if ((found = bin_find_entry(table, bin, hash, entry->key)) != NULL) {
		/* if so: keep the existing data - acquire a writelock */
		lock_rw_wrlock(&found->lock);
	}
	else
	{
		/* if not: add to bin */
		entry->overflow_next = bin->overflow_list;
		bin->overflow_list = entry;
		lru_front(table, entry);
		table->num++;
		table->space_used += need_size;
		/* return the entry that was presented, and lock it */
		found = entry;
		lock_rw_wrlock(&found->lock);
	}
	lock_quick_unlock(&bin->lock);
	if (table->space_used > table->space_max)
		reclaim_space(table, &reclaimlist);
	if (table->num >= table->size)
		table_grow(table);
	lock_quick_unlock(&table->lock);

	/* finish reclaim if any (outside of critical region) */
	while (reclaimlist) {
		struct lruhash_entry* n = reclaimlist->overflow_next;
		void* d = reclaimlist->data;
		(*table->delkeyfunc)(reclaimlist->key, cb_arg);
		(*table->deldatafunc)(d, cb_arg);
		reclaimlist = n;
	}

	/* return the entry that was selected */
	return found;
}

/*
 * For the data part, we want to allocate in rounded increments, so as to reduce the
 * number of calls to XMALLOC
 */

static uint32_t 
mdns_util_suggest_size(uint32_t required_size)
{
	return (required_size <= 512) ? ((required_size <= 256) ? 256 : 512) :
		((required_size + 1023) & 0xFFFFFC00);
}

/*
 * Cache management utilities
 */
static int
mdns_util_skip_name(uint8_t *p)
{
	int x = 0;
	int l;

	for (;;) {
		l = p[x];
		if (l == 0)
		{
			x++;
			break;
		}
		else if (l >= 0xC0)
		{
			x += 2;
			break;
		}
		else
		{
			x += l + 1;
		}
	}
	return x;
}

static int
mdns_util_skip_query(uint8_t *p)
{
	return mdns_util_skip_name(p) + 4;
}

/*
 * Comparison and other functions required for cache management
 */

 /**
 * Calculates the size of an entry.
 *
 * size = mdns_cache_size (key, data).
 */
static size_t mdns_cache_entry_size(void* vkey, void* vdata)
{
	size_t sz = 0;

	if (vkey != NULL)
	{
		sz += sizeof(getdns_mdns_cached_key_header) + ((getdns_mdns_cached_key_header*)vkey)->name_len;
	}

	if (vdata != NULL)
	{
		sz += ((getdns_mdns_cached_record_header*)vdata)->allocated_length;
	}

	return  sz;
}

/** type of function that compares two keys. return 0 if equal. */
static int mdns_cache_key_comp(void* vkey1, void* vkey2)
{
	getdns_mdns_cached_key_header *header1 = (getdns_mdns_cached_key_header*)vkey1;
	getdns_mdns_cached_key_header *header2 = (getdns_mdns_cached_key_header*)vkey2;

	return (header1->record_type == header2->record_type &&
		header1->record_class == header2->record_class &&
		header1->name_len == header2->name_len)
		? memcmp(((uint8_t*)vkey1) + sizeof(getdns_mdns_cached_key_header),
			((uint8_t*)vkey2) + sizeof(getdns_mdns_cached_key_header),
			header1->name_len)
		: -1;
}

/** old keys are deleted.
* markdel() is used first.
* This function is called: func(key, userarg)
* the userarg is set to the context in which the LRU hash table was created
*/
static void msdn_cache_delkey(void* vkey, void* vcontext)
{
	GETDNS_FREE(((struct getdns_context *) vcontext)->mf, vkey);
}

/** old data is deleted. This function is called: func(data, userarg). 
 * Since we use the hash table for both data and requests, need to
 * terminate whatever request was ongoing. TODO: we should have some smarts
 * in cache management and never drop cached entries with active requests.
 */
static void msdn_cache_deldata(void* vdata, void* vcontext)
{
	/* need to terminate the pending queries? */
	getdns_mdns_cached_record_header* header = ((getdns_mdns_cached_record_header*)vdata);

	while (header->netreq_first)
	{
		/* Need to unchain the request from that entry */
		getdns_network_req* netreq = header->netreq_first;
		header->netreq_first = netreq->mdns_netreq_next;
		netreq->mdns_netreq_next = NULL;

		/* TODO: treating as a timeout for now, may consider treating as error */
		netreq->debug_end_time = _getdns_get_time_as_uintt64();
		netreq->state = NET_REQ_TIMED_OUT;
		if (netreq->owner->user_callback) {
			(void)_getdns_context_request_timed_out(netreq->owner);
		}
		_getdns_check_dns_req_complete(netreq->owner);

	}
	GETDNS_FREE(((struct getdns_context *) vcontext)->mf, vdata);
}

/*
 * Create a key in preallocated buffer
 * the allocated size of key should be >= sizeof(getdns_mdns_cached_key_header) + name_len
 */
static void msdn_cache_create_key_in_buffer(
	uint8_t* key, 
	uint8_t * name, int name_len,
	int record_type, int record_class)
{
	getdns_mdns_cached_key_header * header = (getdns_mdns_cached_key_header*)key;
	header->record_type = record_type;
	header->record_class = record_class;
	header->name_len = name_len;
	(void) memcpy(key + sizeof(getdns_mdns_cached_key_header), name, name_len);
}

static uint8_t * mdns_cache_create_key(
	uint8_t * name, int name_len,
	int record_type, int record_class,
	struct getdns_context * context)
{
	uint8_t* key = GETDNS_XMALLOC(context->mf, uint8_t, sizeof(getdns_mdns_cached_key_header) + name_len);

	if (key != NULL)
	{
		msdn_cache_create_key_in_buffer(key, name, name_len, record_type, record_class);
	}

	return key;
}

static uint8_t * mdns_cache_create_data(
	uint8_t * name, int name_len,
	int record_type, int record_class,
	int record_data_len,
	uint64_t current_time,
	struct getdns_context * context)
{
	getdns_mdns_cached_record_header * header;
	int current_index;
	size_t data_size = sizeof(getdns_mdns_cached_record_header) + 12 + name_len + 4;
	size_t alloc_size = mdns_util_suggest_size(data_size + record_data_len + 2 + 2 + 2 + 4 + 2);

	uint8_t* data = GETDNS_XMALLOC(context->mf, uint8_t, alloc_size);

	if (data != NULL)
	{
		header = (getdns_mdns_cached_record_header *)data;
		header->insertion_microsec = current_time;
		header->content_len = data_size;
		header->allocated_length = alloc_size;
		header->netreq_first = NULL;
		current_index = sizeof(getdns_mdns_cached_record_header);
		memset(data + current_index, 0, 12);
		current_index += 12;
		memcpy(data + current_index, name, name_len);
		current_index += name_len;
		data[current_index++] = (uint8_t)(record_type >> 8);
		data[current_index++] = (uint8_t)(record_type);
		data[current_index++] = (uint8_t)(record_class >> 8);
		data[current_index++] = (uint8_t)(record_class);
	}

	return data;
}


/*
 * Add a record.
 */
static int
mdns_add_record_to_cache_entry(struct getdns_context *context,
	uint8_t * old_record, uint8_t ** new_record,
	int record_type, int record_class, int ttl,
	uint8_t * record_data, int record_data_len)
{
	int ret = 0;
	getdns_mdns_cached_record_header *header = (getdns_mdns_cached_record_header*)old_record;
	/* Compute the record length */
	uint32_t record_length = 2 + 2 + 2 + 4 + 2 + record_data_len;
	uint32_t current_length = header->content_len;
	/* update the number of records */
	uint8_t *start_answer_code = old_record + sizeof(getdns_mdns_cached_record_header) + 2 + 2;
	uint16_t nb_answers = (start_answer_code[0] << 8) + start_answer_code[1];
	nb_answers++;
	start_answer_code[0] = (uint8_t)(nb_answers >> 8);
	start_answer_code[1] = (uint8_t)(nb_answers&0xFF);

	/* Update the content length */
	header->content_len += record_length;
	if (header->content_len > header->allocated_length)
	{
		/* realloc to a new length, */
		do {
			header->allocated_length = mdns_util_suggest_size(header->content_len);
		} while (header->content_len > header->allocated_length);

		*new_record = GETDNS_XREALLOC(context->mf, old_record, uint8_t, header->allocated_length); 
	}
	else
	{
		*new_record = old_record;
	}

	if (*new_record == NULL)
	{
		ret = GETDNS_RETURN_MEMORY_ERROR;
	}
	else
	{
		/* copy the record */
		/* First, point name relative to beginning of DNS message */
		(*new_record)[current_length++] = 0xC0;
		(*new_record)[current_length++] = 0x12;
		/* encode the components of the per record header */
		(*new_record)[current_length++] = (uint8_t)((record_type >> 8) & 0xFF);
		(*new_record)[current_length++] = (uint8_t)((record_type)& 0xFF);
		(*new_record)[current_length++] = (uint8_t)((record_class >> 8) & 0xFF);
		(*new_record)[current_length++] = (uint8_t)((record_class)& 0xFF);
		(*new_record)[current_length++] = (uint8_t)((ttl >> 24) & 0xFF);
		(*new_record)[current_length++] = (uint8_t)((ttl >> 16) & 0xFF);
		(*new_record)[current_length++] = (uint8_t)((ttl >> 8) & 0xFF);
		(*new_record)[current_length++] = (uint8_t)((ttl)& 0xFF);
		(*new_record)[current_length++] = (uint8_t)((record_data_len >> 8) & 0xFF);
		(*new_record)[current_length++] = (uint8_t)((record_data_len) & 0xFF);
		memcpy(*new_record + current_length, record_data, record_data_len);
	}

	return ret;
}

static int
mdns_update_cache_ttl_and_prune(struct getdns_context *context,
	uint8_t * old_record, uint8_t ** new_record,
	int record_type, int record_class, int ttl,
	uint8_t * record_data, int record_data_len,
	uint64_t current_time)
{
	/*
	 * Compute the TTL delta
	 */
	int ret = 0;
	getdns_mdns_cached_record_header *header = (getdns_mdns_cached_record_header*)old_record;
	uint32_t delta_t_sec = (uint32_t)((current_time - header->insertion_microsec) / 1000000ll);
	header->insertion_microsec += delta_t_sec * 1000000;
	int message_index;
	int answer_index;
	int nb_answers;
	int nb_answers_left;
	int current_record_length;
	int current_record_data_len;
	uint32_t current_record_ttl;
	int not_matched_yet = (record_data == NULL) ? 0 : 1;
	int current_record_match;
	int last_copied_index;
	int current_hole_index;

	/*
	 * Skip the query
	 */
	message_index = sizeof(getdns_mdns_cached_record_header);
	nb_answers = (old_record[message_index + 4] << 8) | old_record[message_index + 5];
	nb_answers_left = nb_answers;
	answer_index = mdns_util_skip_query(old_record + message_index + 12);
	last_copied_index = answer_index;

	/*
	 * Examine each record
	 */
	for (int i = 0; i < nb_answers; i++)
	{
		current_record_ttl = (old_record[answer_index + 2 + 2 + 2] << 24)
			| (old_record[answer_index + 2 + 2 + 2 + 1] << 16)
			| (old_record[answer_index + 2 + 2 + 2 + 2] << 8)
			| (old_record[answer_index + 2 + 2 + 2 + 3]);

		current_record_data_len = (old_record[answer_index + 2 + 2 + 2 + 4] << 8)
			| (old_record[answer_index + 2 + 2 + 2 + 4 + 1]);

		current_record_length = 2 + 2 + 2 + 4 + 2 + current_record_data_len;

		if (not_matched_yet &&
		    current_record_data_len == record_data_len &&
			memcmp(old_record + answer_index + 2 + 2 + 2 + 4 + 2, record_data, record_data_len) == 0)
		{
			current_record_match = 1;
			not_matched_yet = 0;
			current_record_ttl = ttl;
		}
		else
		{
			/* Not a match */
			current_record_match = 0;

			if (current_record_ttl > delta_t_sec)
			{
				current_record_ttl -= delta_t_sec;
			}
			else
			{
				current_record_ttl = 0;
			}
		}

		if (current_record_ttl != 0)
		{
			nb_answers_left--;

			/* this record should be compacted away */
			if (current_hole_index == 0)
			{
				/* encountering the first hole in the message,
				 * no need to copy anything yet.
				 */
				last_copied_index = answer_index;
			}
			else if (current_hole_index != answer_index)
			{
				/* copy the data from hole to answer */
				memmove(old_record + last_copied_index, old_record + current_hole_index,
					answer_index - current_hole_index);
				last_copied_index += answer_index - current_hole_index;
			}
			
			/* in all cases, the current hole begins after the message's encoding */
			current_hole_index = answer_index + current_record_length;
		}
		else
		{
			/* keeping this record, but updating the TTL */
			old_record[answer_index + 2 + 2 + 2] = (uint8_t)(current_record_ttl >> 24);
			old_record[answer_index + 2 + 2 + 2 + 1] = (uint8_t)(current_record_ttl >> 16);
			old_record[answer_index + 2 + 2 + 2 + 2] = (uint8_t)(current_record_ttl >> 8);
			old_record[answer_index + 2 + 2 + 2 + 3] = (uint8_t)(current_record_ttl);
		}
		/* progress to the next record */
		answer_index += current_record_length;
	}

	/* if necessary, copy the pending data */
	if (current_hole_index != answer_index)
	{
		/* copy the data from hole to last answer */
		memmove(old_record + last_copied_index, old_record + current_hole_index,
			answer_index - current_hole_index);
		last_copied_index += answer_index - current_hole_index;
	}

	/* if some records were deleted, update the record headers */
	if (nb_answers != nb_answers_left)
	{
		header->content_len = last_copied_index;
		old_record[message_index + 4] = (uint8_t)(nb_answers >> 8);
		old_record[message_index + 5] = (uint8_t)(nb_answers);
	}

	/*
	* if the update was never seen, ask for an addition
	*/
	if (ttl == 0 && not_matched_yet)
	{
		mdns_add_record_to_cache_entry(context, old_record, new_record,
			record_type, record_class, ttl, record_data, record_data_len);
		nb_answers_left++;
	}
	else
	{
		*new_record = old_record;
	}

	/*
	 * TODO: if there are no record left standing, return a signal that the cache should be pruned.
	 */

	return ret;
}


/*
* Add entry function for the MDNS record cache.
*/
static int
mdns_propose_entry_to_cache(
	struct getdns_context *context,
	uint8_t * name, int name_len,
	int record_type, int record_class, int ttl,
	uint8_t * record_data, int record_data_len,
	getdns_network_req * netreq,
	uint64_t current_time)
{
	int ret = 0;
	size_t required_memory = 0;
	uint8_t temp_key[256 + sizeof(getdns_mdns_cached_key_header)];
	hashvalue_type hash;
	struct lruhash_entry *entry, *new_entry;
	uint8_t *key, *data;
	getdns_mdns_cached_record_header * header;

	msdn_cache_create_key_in_buffer(temp_key, name, name_len, record_type, record_class);

	
	/* TODO: make hash init value a random number in the context, for defense against DOS */
	hash = hashlittle(temp_key, name_len + sizeof(getdns_mdns_cached_key_header), 0xCAC8E);

	entry = lruhash_lookup(context->mdns_cache, hash, temp_key, 1);

	if (entry == NULL && ttl != 0)
	{
		/*
		 * Create an empty entry.
		 */
		key = mdns_cache_create_key(name, name_len, record_type, record_class, context);
		data = mdns_cache_create_data(name, name_len, record_type, record_class,
				record_data_len, current_time, context);
		new_entry = GETDNS_XMALLOC(context->mf, struct lruhash_entry, 1);

		if (key == NULL || data == NULL || new_entry == NULL)
		{
			if (key != NULL)
			{
				GETDNS_FREE(context->mf, key);
				key = NULL;
			}

			if (data != NULL)
			{
				GETDNS_FREE(context->mf, data);
				data = NULL;
			}

			if (new_entry != NULL)
			{
				GETDNS_FREE(context->mf, new_entry);
				new_entry = NULL;
			}

		}
		else
		{
			memset(new_entry, 0, sizeof(struct lruhash_entry));
			lock_rw_init(new_entry->lock);
			new_entry->hash = hash;
			new_entry->key = key;
			new_entry->data = data;

			entry = lruhash_insert_or_retrieve(context->mdns_cache, hash, new_entry, data, NULL);

			if (entry != new_entry)
			{
				lock_rw_destroy(new_entry->lock);
				GETDNS_FREE(context->mf, new_entry);
			}
		}
	}

	if (entry != NULL)
	{
		if (record_data != NULL && record_data_len > 0)
			ret = mdns_update_cache_ttl_and_prune(context,
				(uint8_t*)entry->data, &data,
				record_type, record_class, ttl, record_data, record_data_len,
				current_time);

		if (netreq != NULL)
		{
			/* chain the continuous request to the cache line */
			header = (getdns_mdns_cached_record_header *) entry->data;
			netreq->mdns_netreq_next = header->netreq_first;
			header->netreq_first = netreq;
		}

		/* then, unlock the entry */
		lock_rw_unlock(entry->lock);

		/* TODO: if the entry was marked for deletion, move it to the bottom of the LRU */
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
 * Multicast receive event callback
 */
static void
mdns_udp_multicast_read_cb(void *userarg)
{
	mdns_network_connection * cnx = (mdns_network_connection *)userarg;
	ssize_t       read;
	DEBUG_MDNS("%s %-35s: CTX: %p, NET=%d \n", MDNS_DEBUG_MREAD,
		__FUNCTION__, cnx->context, cnx->addr_mcast.ss_family);

	GETDNS_CLEAR_EVENT(
		cnx->context->extension, &cnx->event);

	read = recvfrom(cnx->fd, (void *)cnx->response,
		sizeof(cnx->response), 0, NULL, NULL);


	if (read == -1 && _getdns_EWOULDBLOCK)
		return; /* TODO: this will stop the receive loop! */

	if (read >= GLDNS_HEADER_SIZE)
	{
		/* parse the response, find the relevant queries, submit the records to the cache */

		/*
		netreq->response_len = read;
		netreq->debug_end_time = _getdns_get_time_as_uintt64();
		netreq->state = NET_REQ_FINISHED;
		_getdns_check_dns_req_complete(dnsreq);
		*/
	}
	else
	{
		/* bogus packet.. Should log. */
	}

	/*
	 * Relaunch the event, so we can go read the next packet.
	 */
	GETDNS_SCHEDULE_EVENT(
		cnx->context->extension, cnx->fd, 0,
		getdns_eventloop_event_init(&cnx->event, cnx,
			mdns_udp_multicast_read_cb, NULL, NULL));
}

/*
 * Create the two required multicast sockets
 */
static int mdns_open_ipv4_multicast(SOCKADDR_STORAGE* mcast_dest, int* mcast_dest_len)
{
	getdns_return_t ret = 0;
	SOCKET fd4 = -1;
	SOCKADDR_IN ipv4_dest;
	SOCKADDR_IN ipv4_port;
	uint8_t so_reuse_bool = 1;
	uint8_t ttl = 255;
	IP_MREQ mreq4;

	memset(&mcast_dest, 0, sizeof(SOCKADDR_STORAGE));
	*mcast_dest_len = 0;
	memset(&ipv4_dest, 0, sizeof(ipv4_dest));
	memset(&ipv4_port, 0, sizeof(ipv4_dest));
	ipv4_dest.sin_family = AF_INET;
	ipv4_dest.sin_port = htons(MDNS_MCAST_PORT);
	ipv4_dest.sin_addr.S_un.S_addr = htonl(MDNS_MCAST_IPV4_LONG);
	ipv4_port.sin_family = AF_INET;
	ipv4_port.sin_port = htons(MDNS_MCAST_PORT);


	fd4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (fd4 != -1)
	{
		/*
		 * No need to test the output of the so_reuse call,
		 * since the only result that matters is that of bind.
		 */
		(void)setsockopt(fd4, SOL_SOCKET, SO_REUSEADDR
			, (const char*)&so_reuse_bool, (int) sizeof(BOOL));

		if (bind(fd4, (SOCKADDR*)&ipv4_port, sizeof(ipv4_port)) != 0)
		{
			ret = -1;
		}
		else
		{
			mreq4.imr_multiaddr = ipv4_dest.sin_addr;
			mreq4.imr_interface = ipv4_port.sin_addr;

			if (setsockopt(fd4, IPPROTO_IP, IP_ADD_MEMBERSHIP
				, (const char*)&mreq4, (int) sizeof(mreq4)) != 0)
			{
				ret = -1;
			}
			else if (setsockopt(fd4, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) != 0)
			{
				ret = -1;
			}
		}
	}

	if (ret != 0 && fd4 != -1)
	{
#ifdef USE_WINSOCK
			closesocket(fd4);
#else
			close(fd4);
#endif
			fd4 = -1;
	}

	if (ret == 0)
	{
		memcpy(&mcast_dest, &ipv4_dest, sizeof(ipv4_dest));
		*mcast_dest_len = sizeof(ipv4_dest);
	}

	return fd4;
}

static int mdns_open_ipv6_multicast(SOCKADDR_STORAGE* mcast_dest, int* mcast_dest_len)
{
	getdns_return_t ret = 0;
	SOCKET fd6 = -1;
	SOCKADDR_IN6 ipv6_dest;
	SOCKADDR_IN6 ipv6_port;
	uint8_t so_reuse_bool = 1;
	uint8_t ttl = 255;
	IPV6_MREQ mreq6;

	memset(&mcast_dest, 0, sizeof(SOCKADDR_STORAGE));
	*mcast_dest_len = 0;
	memset(&ipv6_dest, 0, sizeof(ipv6_dest));
	memset(&ipv6_port, 0, sizeof(ipv6_dest));
	ipv6_dest.sin6_family = AF_INET6;
	ipv6_dest.sin6_port = htons(MDNS_MCAST_PORT);
	ipv6_port.sin6_family = AF_INET6;
	ipv6_port.sin6_port = htons(MDNS_MCAST_PORT);
	memcpy(&ipv6_dest.sin6_addr
		, mdns_mcast_ipv6, sizeof(mdns_mcast_ipv6));


	fd6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	if (fd6 != -1)
	{
		/*
		* No need to test the output of the so_reuse call,
		* since the only result that matters is that of bind.
		*/
		(void)setsockopt(fd6, SOL_SOCKET, SO_REUSEADDR
			, (const char*)&so_reuse_bool, (int) sizeof(BOOL));

		if (bind(fd6, (SOCKADDR*)&ipv6_port, sizeof(ipv6_port)) != 0)
		{
			ret = -1;
		}
		else
		{
			memcpy(&mreq6.ipv6mr_multiaddr
				, &ipv6_dest.sin6_addr, sizeof(mreq6.ipv6mr_multiaddr));
			memcpy(&mreq6.ipv6mr_interface
				, &ipv6_port.sin6_addr, sizeof(mreq6.ipv6mr_interface));

			if (setsockopt(fd6, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP
				, (const char*)&mreq6, (int) sizeof(mreq6)) != 0)
			{
				ret = -1;
			}
			else if (setsockopt(fd6, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) != 0)
			{
				ret = -1;
			}
		}
	}

	if (ret != 0 && fd6 != -1)
	{
#ifdef USE_WINSOCK
		closesocket(fd6);
#else
		close(fd6);
#endif
		fd6 = -1;
	}

	if (ret == 0)
	{
		memcpy(&mcast_dest, &ipv6_dest, sizeof(ipv6_dest));
		*mcast_dest_len = sizeof(ipv6_dest);
	}
	return fd6;
}

/*
 * Delayed opening of the MDNS sockets, and launch of the MDNS listeners
 */
static getdns_return_t mdns_delayed_network_init(struct getdns_context *context)
{
	getdns_return_t ret = 0;

	if (context->mdns_extended_support == 2)
	{
		context->mdns_cache = lruhash_create(128, 10000000,
			mdns_cache_entry_size, mdns_cache_key_comp,
			msdn_cache_delkey, msdn_cache_deldata,
			context);

		if (context->mdns_cache == NULL)
		{
			ret = GETDNS_RETURN_MEMORY_ERROR;
		}
		else
		{
			context->mdns_connection = (mdns_network_connection *)
				GETDNS_XMALLOC(context->my_mf, mdns_network_connection, 2);

			if (context->mdns_connection == NULL)
			{
				ret = GETDNS_RETURN_MEMORY_ERROR;
			}
			else
			{
				context->mdns_connection_nb = 2;

				context->mdns_connection[0].fd = mdns_open_ipv4_multicast(
					&context->mdns_connection[0].addr_mcast
					, &context->mdns_connection[0].addr_mcast_len);
				context->mdns_connection[1].fd = mdns_open_ipv6_multicast(
					&context->mdns_connection[0].addr_mcast
					, &context->mdns_connection[0].addr_mcast_len);

				if (context->mdns_connection[0].fd == -1 ||
					context->mdns_connection[1].fd == -1)
				{
					ret = GETDNS_RETURN_GENERIC_ERROR;
				}
				else
				{
					/* TODO: launch the receive loops */
					for (int i = 0; i < 2; i++)
					{
						GETDNS_CLEAR_EVENT(context->extension, &context->mdns_connection[i].event);
						GETDNS_SCHEDULE_EVENT(
							context->extension, context->mdns_connection[i].fd, 0,
							getdns_eventloop_event_init(&context->mdns_connection[i].event,
								&context->mdns_connection[i],
								mdns_udp_multicast_read_cb, NULL, NULL));
					}
				}

				if (ret != 0)
				{
					for (int i = 0; i < 2; i++)
					{
						if (context->mdns_connection[i].fd != -1)
						{

							GETDNS_CLEAR_EVENT(context->extension
								, &context->mdns_connection[i].event);
#ifdef USE_WINSOCK
							closesocket(context->mdns_connection[i].fd);
#else
							close(context->mdns_connection[i].fd);
#endif
						}
					}

					GETDNS_FREE(context->my_mf, context->mdns_connection);
					context->mdns_connection = NULL;
					context->mdns_connection_nb = 0;
				}
			} /* mdns-connection != NULL */

			if (ret != 0)
			{
				/* delete the cache that was just created, since the network connection failed */
				lruhash_delete(context->mdns_cache);
				context->mdns_cache = NULL;
			}
		} /* cache != NULL */

		context->mdns_extended_support = (ret == 0) ? 1 : 0;
	}

	return ret;
}

/*
 * Initialize a continuous query from netreq
 */
static getdns_return_t mdns_initialize_continuous_request(getdns_network_req *netreq)
{
	int ret = 0;
	getdns_dns_req *dnsreq = netreq->owner;
	struct getdns_context *context = dnsreq->context;

	ret = mdns_propose_entry_to_cache(context, dnsreq->name, dnsreq->name_len,
		netreq->request_type, dnsreq->request_class, 1, NULL, 0,
		netreq, _getdns_get_time_as_uintt64());

	/* to do: queue message request to socket */

	return ret;
}

/*
 * Initialize the MDNS part of the context structure.
 */
void _getdns_mdns_context_init(struct getdns_context *context)
{
	context->mdns_extended_support = 2; /* 0 = no support, 1 = supported, 2 = initialization needed */
	context->mdns_connection = NULL;
	context->mdns_connection_nb = 0;
	context->mdns_cache = NULL;
}

/*
 * Delete all the data allocated for MDNS in a context
 */
void _getdns_mdns_context_destroy(struct getdns_context *context)
{
	/* Clear all the cached records. This will terminate all pending network requests */
	if (context->mdns_cache != NULL)
	{
		lruhash_delete(context->mdns_cache);
		context->mdns_cache = NULL;
	}
	/* Close the connections */
	if (context->mdns_connection != NULL)
	{
		for (int i = 0; i < context->mdns_connection_nb; i++)
		{
			/* suppress the receive event */
			GETDNS_CLEAR_EVENT(context->extension, &context->mdns_connection[i].event);
			/* close the socket */
#ifdef USE_WINSOCK
			closesocket(context->mdns_connection[i].fd);
#else
			close(context->mdns_connection[i].fd);
#endif
		}

		GETDNS_FREE(context->mf, context->mdns_connection);
		context->mdns_connection = NULL;
		context->mdns_connection_nb = 0;
	}
}

/* TODO: actualy delete what is required.. */
static void
mdns_cleanup(getdns_network_req *netreq)
{
	DEBUG_MDNS("%s %-35s: MSG: %p\n",
		MDNS_DEBUG_CLEANUP, __FUNCTION__, netreq);
	getdns_dns_req *dnsreq = netreq->owner;

	GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);
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
