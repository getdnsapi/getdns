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
#include "getdns_core_only.h"

/* stuff to make it compile pedantically */
#define UNUSED_PARAM(x) ((void)(x))


getdns_return_t
getdns_list_get_length(struct getdns_list *list, size_t *answer)
{
    int retval = GETDNS_RETURN_NO_SUCH_LIST_ITEM;

    if(list != NULL && answer != NULL)
    {
        retval = GETDNS_RETURN_GOOD;
        *answer = list->numinuse;
    }

    return retval;
} /* getdns_list_get_length */

/*---------------------------------------- getdns_list_get_data_type */
getdns_return_t 
getdns_list_get_data_type(struct getdns_list *list, size_t index, getdns_data_type *answer)
{
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_LIST_ITEM;

    if(list != NULL && index < list->numinuse)
    {
        *answer = list->items[index].dtype;
        retval = GETDNS_RETURN_GOOD;
    }
    return retval;
} /* getdns_list_get_data_type */

getdns_return_t getdns_list_get_dict(struct getdns_list *this_list, size_t index, struct getdns_dict **answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

/*---------------------------------------- getdns_list_get_list */
getdns_return_t
getdns_list_get_list(struct getdns_list *list, size_t index, struct getdns_list **answer)
{
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_LIST_ITEM;

    if(list != NULL && index < list->numinuse)
    {
        if(list->items[index].dtype != t_list)
            retval = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
        else
        {
            *answer = list->items[index].data.list;
            retval = GETDNS_RETURN_GOOD;
        }
    }

    return retval;
} /* getdns_list_get_list */

getdns_return_t getdns_list_get_bindata(struct getdns_list *this_list, size_t index, struct getdns_bindata **answer)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(answer); return GETDNS_RETURN_GOOD; }

/*---------------------------------------- getdns_list_get_int */
getdns_return_t
getdns_list_get_int(struct getdns_list *list, size_t index, uint32_t *answer)
{
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_LIST_ITEM;

    if(list != NULL && index < list->numinuse)
    {
        if(list->items[index].dtype != t_int)
            retval = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
        else
        {
            *answer = list->items[index].data.n;
            retval = GETDNS_RETURN_GOOD;
        }
    }

    return retval;
} /* getdns_list_get_int */

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
    getdns_return_t retval = GETDNS_RETURN_GENERIC_ERROR;
    int i;
    struct getdns_list_item *newlist;

    if(list != NULL)
    {
        newlist = (struct getdns_list_item *) realloc(list->items
         , (list->numalloc + GETDNS_LIST_BLOCKSZ) * sizeof(struct getdns_list_item));
        if(newlist != NULL)
        {
            list->items = newlist;
            for(i=list->numalloc; i<list->numalloc + GETDNS_LIST_BLOCKSZ; i++)
            {
                list->items[i].inuse = false;
                list->items[i].dtype = t_invalid;
            }
            list->numalloc += GETDNS_LIST_BLOCKSZ;
            retval = GETDNS_RETURN_GOOD;
        }
    }

    return retval;
} /* getdns_list_alloc */

/*---------------------------------------- getdns_list_create */
struct getdns_list *
getdns_list_create()
{
    struct getdns_list *list = NULL;

    list = (struct getdns_list *) malloc(sizeof(struct getdns_list));
    if(list != NULL)
    {
        list->numalloc = 0;
        list->numinuse = 0;
        list->items = NULL;

        getdns_list_realloc(list);
    }

    return list;
} /* getdns_list_create */

/*---------------------------------------- getdns_list_destroy */
void
getdns_list_destroy(struct getdns_list *list)
{
    if(list != NULL)
    {
        if(list->items != NULL)
            free(list->items);
        free(list);
    }
} /* getdns_list_destroy */

/*---------------------------------------- getdns_list_add_item */
getdns_return_t
getdns_list_add_item(struct getdns_list *list, size_t *index)
{
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_LIST_ITEM;
    if(list != NULL && index != NULL)
    {
        if(list->numalloc == list->numinuse)
            retval = getdns_list_realloc(list);
        else
            retval = GETDNS_RETURN_GOOD;

        if(retval == GETDNS_RETURN_GOOD)
        {
            *index = list->numinuse;
            list->items[*index].inuse = true;
            list->numinuse++;
        }
    }
    return retval;
} /* getdns_list_add_item */

getdns_return_t getdns_list_set_dict(struct getdns_list *this_list, size_t index, struct getdns_dict *child_dict)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(child_dict); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_set_list(struct getdns_list *this_list, size_t index, struct getdns_list *child_list)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(child_list); return GETDNS_RETURN_GOOD; }

getdns_return_t getdns_list_set_bindata(struct getdns_list *this_list, size_t index, struct getdns_bindata *child_bindata)
{ UNUSED_PARAM(this_list); UNUSED_PARAM(index); UNUSED_PARAM(child_bindata); return GETDNS_RETURN_GOOD; }

/*---------------------------------------- getdns_list_set */
getdns_return_t
getdns_list_set_int(struct getdns_list *list, size_t index, uint32_t child_uint32)
{
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_LIST_ITEM;

    if(list != NULL)
    {
        if(list->numinuse > index)
        {
            list->items[index].dtype = t_int;
            list->items[index].data.n = child_uint32;
        }
    }

    return retval;
} /* getdns_list_set_int */

/* getdns_list.c */
