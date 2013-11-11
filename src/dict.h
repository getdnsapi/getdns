/**
 *
 * /brief getdns dict data type management functions
 *
 *
 */

/*
 * Copyright (c) 2013, NLNet Labs, Versign, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the name of the <organization> nor the
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

#ifndef _GETDNS_DICT_H_
#define _GETDNS_DICT_H_

#include <getdns/getdns.h>
#include <ldns/rbtree.h>

union getdns_item
{
	struct getdns_list *list;
	struct getdns_dict *dict;
	uint32_t n;
	struct getdns_bindata *bindata;
};

/**
 * this structure represents a single item in a dictionary type
 */
struct getdns_dict_item
{
	ldns_rbnode_t node;
	getdns_data_type dtype;
	union getdns_item data;
};

/**
 * getdns dictionary data type
 * Use helper functions getdns_dict_* to manipulate and iterate dictionaries
 * dict is implemented using the t*() functions for manipulating binary search
 * trees in the std library.  The internal implementation may change so the
 * application should stick to the helper functions.
 */
struct getdns_dict
{
	ldns_rbtree_t root;
	getdns_context_t context;
};

#endif

/* dict.h */
