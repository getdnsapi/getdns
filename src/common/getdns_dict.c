/**
 *
 * /brief getdns list management functions
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

#include <getdns_libevent.h>

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))

getdns_return_t getdns_dict_get_names(struct getdns_dict *this_dict, struct getdns_list **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_data_type(struct getdns_dict *this_dict, char *name, getdns_data_type *answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_dict(struct getdns_dict *this_dict, char *name, struct getdns_dict **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_list(struct getdns_dict *this_dict, char *name, struct getdns_list **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_bindata(struct getdns_dict *this_dict, char *name, struct getdns_bindata **answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_get_int(struct getdns_dict *this_dict, char *name, uint32_t *answer)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

struct getdns_dict * getdns_dict_create()
{ return NULL; }

void getdns_dict_destroy(struct getdns_dict *this_dict)
{ UNUSED_PARAM(this_dict); }

getdns_return_t getdns_dict_set_dict(struct getdns_dict *this_dict, char *name, struct getdns_dict *child_dict)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_dict); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_set_list(struct getdns_dict *this_dict, char *name, struct getdns_list *child_list)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_list); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_set_bindata(struct getdns_dict *this_dict, char *name, struct getdns_bindata *child_bindata)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_bindata); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_dict_set_int(struct getdns_dict *this_dict, char *name, uint32_t child_uint32)
{ UNUSED_PARAM(this_dict); UNUSED_PARAM(name); UNUSED_PARAM(child_uint32); return GETDNS_RETURN_GOOD; }

char *
getdns_pretty_print_dict(
	struct getdns_dict     *some_dict
)
{ UNUSED_PARAM(some_dict); return NULL; }

/* getdns_dict.c */
