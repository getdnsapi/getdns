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
#ifndef _GETDNS_LIST_H_
#define _GETDNS_LIST_H_

#include <getdns/getdns.h>

#define GETDNS_LIST_BLOCKSZ 10

/**
 * this structure represents a single item in a list
 */
struct getdns_list_item
{
	int inuse;
	getdns_data_type dtype;
	union
	{
		getdns_list *list;
		getdns_dict *dict;
		int n;
		getdns_bindata *bindata;
	} data;
};

/**
 * getdns list data type
 * Use helper functions getdns_list_* to manipulate and iterate lists
 * lists are implemented as arrays internally since the helper functions
 * like to reference indexes in the list.  Elements are allocated in blocks
 * and then marked valid as they are used and invalid as they are not used
 * The use cases do not justify working too hard at shrinking the structures.
 * Indexes are 0 based.
 */
struct getdns_list
{
	int numalloc;
	int numinuse;
	struct getdns_list_item *items;
};

#endif
