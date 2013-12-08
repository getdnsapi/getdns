/**
 *
 * /brief getdns list management functions
 * 
 * This is the meat of the API
 * Originally taken from the getdns API description pseudo implementation.
 *
 */

/*
 * Copyright (c) 2013, Versign, Inc.
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

#include <string.h>
#include "types-internal.h"
#include "util-internal.h"
#include "list.h"

/*---------------------------------------- getdns_list_get_length */
getdns_return_t
getdns_list_get_length(struct getdns_list * list, size_t * answer)
{
	if (!list || !answer)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	*answer = list->numinuse;
	return GETDNS_RETURN_GOOD;;
}				/* getdns_list_get_length */

/*---------------------------------------- getdns_list_get_data_type */
getdns_return_t
getdns_list_get_data_type(struct getdns_list * list, size_t index,
    getdns_data_type * answer)
{
	if (!list || index >= list->numinuse)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	*answer = list->items[index].dtype;
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_get_data_type */

/*---------------------------------------- getdns_list_get_dict */
getdns_return_t
getdns_list_get_dict(struct getdns_list * list, size_t index,
    struct getdns_dict ** answer)
{
	if (!list || index >= list->numinuse)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	if (list->items[index].dtype != t_dict)
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;

	*answer = list->items[index].data.dict;
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_get_dict */

/*---------------------------------------- getdns_list_get_list */
getdns_return_t
getdns_list_get_list(struct getdns_list * list, size_t index,
    struct getdns_list ** answer)
{

	if (!list || index >= list->numinuse)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	if (list->items[index].dtype != t_list)
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;

	*answer = list->items[index].data.list;
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_get_list */

/*---------------------------------------- getdns_list_get_bindata */
getdns_return_t
getdns_list_get_bindata(struct getdns_list * list, size_t index,
    struct getdns_bindata ** answer)
{
	if (!list || index >= list->numinuse)
		return  GETDNS_RETURN_NO_SUCH_LIST_ITEM;
	
	if (list->items[index].dtype != t_bindata)
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;

	*answer = list->items[index].data.bindata;
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_get_bindata */

/*---------------------------------------- getdns_list_get_int */
getdns_return_t
getdns_list_get_int(struct getdns_list * list, size_t index, uint32_t * answer)
{
	if (!list || index >= list->numinuse)
		return  GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	if (list->items[index].dtype != t_int)
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;

	*answer = list->items[index].data.n;
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_get_int */

/*---------------------------------------- getdns_list_realloc */
/**
  * private function (API users should not be calling this)
  * allocates a block of items, should be called when a list needs to grow
  * preserves the existing items
  * in case of an error the list should be considered unusable
  * @return GETDNS_RETURN_GOOD on success, GETDNS_RETURN_GENERIC_ERROR if out of memory
  */
getdns_return_t
getdns_list_realloc(struct getdns_list *list)
{
	struct getdns_list_item *newlist;

	if (!list)
		return GETDNS_RETURN_GENERIC_ERROR;

	newlist = GETDNS_XREALLOC(list->mf, list->items,
	    struct getdns_list_item,
	    list->numalloc + GETDNS_LIST_BLOCKSZ);
	if (!newlist)
		return GETDNS_RETURN_GENERIC_ERROR;

	list->items = newlist;
	list->numalloc += GETDNS_LIST_BLOCKSZ;
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_realloc */

/*---------------------------------------- getdns_list_copy */
getdns_return_t
getdns_list_copy(struct getdns_list * srclist, struct getdns_list ** dstlist)
{
	int i;
	size_t index;
	getdns_return_t retval;

	if (!dstlist)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	if (!srclist) {
		*dstlist = NULL;
		return GETDNS_RETURN_GOOD;
	}
	*dstlist = getdns_list_create_with_memory_functions(
	    srclist->mf.mf.pln.malloc,
	    srclist->mf.mf.pln.realloc,
	    srclist->mf.mf.pln.free
	);
	if (!dstlist)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	for (i = 0; i < srclist->numinuse; i++) {
		retval = getdns_list_add_item(*dstlist, &index);
		if (retval != GETDNS_RETURN_GOOD) {
			getdns_list_destroy(*dstlist);
			*dstlist = NULL;
			return retval;
		}
		switch (srclist->items[i].dtype) {
		case t_int:
			retval = getdns_list_set_int(*dstlist, index,
			                             srclist->items[i].data.n);
			break;

		case t_list:
			retval =getdns_list_set_list(*dstlist, index,
			    srclist->items[i].data.list);
			break;
		
		case t_bindata:
			retval = getdns_list_set_bindata(*dstlist, index,
			    srclist->items[i].data.bindata);
			break;

		case t_dict:
			retval = getdns_list_set_dict(*dstlist, index,
			    srclist->items[i].data.dict);
			break;
		}
		if (retval != GETDNS_RETURN_GOOD) {
			getdns_list_destroy(*dstlist);
			*dstlist = NULL;
			return retval;
		}
	}
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_copy */

struct getdns_list *
getdns_list_create_with_memory_functions(void *(*malloc)(size_t),
    void *(*realloc)(void *, size_t), void (*free)(void *))
{
	struct getdns_list *list;

	if (!malloc || !realloc || !free)
		return NULL;

	list = (struct getdns_list *)(*malloc)(sizeof(struct getdns_list));
	if (!list)
		return NULL;
	
	list->mf.mf_arg         = MF_PLAIN;
	list->mf.mf.pln.malloc  = malloc;
	list->mf.mf.pln.realloc = realloc;
	list->mf.mf.pln.free    = free;

	list->numalloc = 0;
	list->numinuse = 0;
	list->items = NULL;
	if (getdns_list_realloc(list) != GETDNS_RETURN_GOOD) {
		getdns_list_destroy(list);
		return NULL;
	}
	return list;
}

/*-------------------------- getdns_list_create_with_context */
struct getdns_list *
getdns_list_create_with_context(struct getdns_context *context)
{
	if (context)
		return getdns_list_create_with_memory_functions(
		    context->mf.mf.pln.malloc,
		    context->mf.mf.pln.realloc,
		    context->mf.mf.pln.free
		);
	else
		return getdns_list_create_with_memory_functions(malloc,
		    realloc, free);
}			/* getdns_list_create_with_context */

/*---------------------------------------- getdns_list_create */
struct getdns_list *
getdns_list_create()
{
	return getdns_list_create_with_context(NULL);
}				/* getdns_list_create */

/*---------------------------------------- getdns_list_destroy */
void
getdns_list_destroy(struct getdns_list *list)
{
	int i;

	if (!list)
		return;

	for (i = 0; i < list->numinuse; i++) {
		switch (list->items[i].dtype) {
		case t_dict:
			getdns_dict_destroy(list->items[i].data.dict);
			break;

		case t_list:
			getdns_list_destroy(list->items[i].data.list);
			break;

		case t_bindata:
			getdns_bindata_destroy(&list->mf,
			    list->items[i].data.bindata);
			break;

		default:
			break;
		}
	}

	if (list->items)
		GETDNS_FREE(list->mf, list->items);
	GETDNS_FREE(list->mf, list);
}				/* getdns_list_destroy */

/*---------------------------------------- getdns_list_add_item */
getdns_return_t
getdns_list_add_item(struct getdns_list *list, size_t * index)
{
	getdns_return_t retval;

	if (!list || !index)
		return  GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	if (list->numalloc == list->numinuse) {
		retval = getdns_list_realloc(list);
		if (retval != GETDNS_RETURN_GOOD)
			return retval;
	}
	*index = list->numinuse;
	list->numinuse++;
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_add_item */

/*---------------------------------------- getdns_list_set_dict */
getdns_return_t
getdns_list_set_dict(struct getdns_list * list, size_t index,
    struct getdns_dict * child_dict)
{
	struct getdns_dict *newdict;
	getdns_return_t retval;

	if (!list || !child_dict)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	if (index >= list->numinuse)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	retval = getdns_dict_copy(child_dict, &newdict);
	if (retval != GETDNS_RETURN_GOOD)
		return retval;

	if (index == list->numinuse) {
		retval = getdns_list_add_item(list, &index);
		if (retval != GETDNS_RETURN_GOOD)
			return retval;
	}
	list->items[index].dtype = t_dict;
	list->items[index].data.dict = newdict;
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_set_dict */

/*---------------------------------------- getdns_list_set_list */
getdns_return_t
getdns_list_set_list(struct getdns_list * list, size_t index,
    struct getdns_list * child_list)
{
	struct getdns_list *newlist;
	getdns_return_t retval;

	if (!list || !child_list)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	if (index >= list->numinuse)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	retval = getdns_list_copy(child_list, &newlist);
	if (retval != GETDNS_RETURN_GOOD)
		return retval;

	if (index == list->numinuse) {
		retval = getdns_list_add_item(list, &index);
		if (retval != GETDNS_RETURN_GOOD)
			return retval;
	}
	list->items[index].dtype = t_list;
	list->items[index].data.list = newlist;
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_set_list */

/*---------------------------------------- getdns_list_set_bindata */
getdns_return_t
getdns_list_set_bindata(struct getdns_list * list, size_t index,
    struct getdns_bindata * child_bindata)
{
	struct getdns_bindata *newbindata;
	getdns_return_t retval;

	if (!list || !child_bindata)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	if (index >= list->numinuse)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	newbindata = getdns_bindata_copy(&list->mf, child_bindata);
	if (!newbindata)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	if (index == list->numinuse) {
		retval = getdns_list_add_item(list, &index);
		if (retval != GETDNS_RETURN_GOOD)
			return retval;
	}
	list->items[index].dtype = t_bindata;
	list->items[index].data.bindata = newbindata;
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_set_bindata */

/*---------------------------------------- getdns_list_set_int */
getdns_return_t
getdns_list_set_int(struct getdns_list * list, size_t index,
    uint32_t child_int)
{
	getdns_return_t retval;

	if (!list)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	if (index >= list->numinuse)
		return GETDNS_RETURN_NO_SUCH_LIST_ITEM;

	if (index == list->numinuse) {
		retval = getdns_list_add_item(list, &index);
		if (retval != GETDNS_RETURN_GOOD)
			return retval;
	}
	list->items[index].dtype = t_int;
	list->items[index].data.n = child_int;
	return GETDNS_RETURN_GOOD;
}				/* getdns_list_set_int */
/* getdns_list.c */

